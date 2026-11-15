package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bropines/rdpanel/internal/auth"
	"github.com/bropines/rdpanel/internal/store"
)

// ConfirmPath is where the confirmation page of a client flow posts.
const ConfirmPath = "/api/oidc/confirm"

// SecondFactor is a user's TOTP (the panel's TOTP service).
type SecondFactor interface {
	Enrolled(ctx context.Context, userID int64) (bool, error)
	Verify(ctx context.Context, userID int64, code string) (bool, error)
}

// EmailFactorFunc reports whether u must enter an e-mailed code at sign-in
// (users without TOTP).
type EmailFactorFunc func(ctx context.Context, u *store.User) (bool, error)

var (
	errCancelled   = &flowError{"cancelled", "Sign-in was cancelled."}
	errEmailFactor = &flowError{"email_factor", "This account signs in with a code sent by e-mail, which RustDesk cannot ask for after an identity provider. Sign in with your password in RustDesk instead."}
	errCode        = &flowError{"code_invalid", "Invalid verification code."}
	errTooMany     = &flowError{"rate_limited", "Too many attempts. Wait a few minutes and try again."}
)

const confirmAD = "oidc-client-confirm"

// sealConfirm returns the token the confirmation form carries: the state and
// the user the IdP named, sealed so that only the browser that got the page
// (after signing in at the IdP) can post it.
func (s *Service) sealConfirm(stateID, userID int64) (string, error) {
	b, err := s.aead.SealString(fmt.Sprintf("%d:%d", stateID, userID), confirmAD)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) openConfirm(token string) (stateID, userID int64, ok bool) {
	if token == "" || len(token) > 512 {
		return 0, 0, false
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, 0, false
	}
	plain, err := s.aead.OpenString(b, confirmAD)
	if err != nil {
		return 0, 0, false
	}
	a, c, found := strings.Cut(plain, ":")
	if !found {
		return 0, 0, false
	}
	stateID, err1 := strconv.ParseInt(a, 10, 64)
	userID, err2 := strconv.ParseInt(c, 10, 64)
	return stateID, userID, err1 == nil && err2 == nil
}

func (s *Service) totpEnrolled(ctx context.Context, userID int64) (bool, error) {
	if s.secondFactor == nil {
		return false, nil
	}
	return s.secondFactor.Enrolled(ctx, userID)
}

// askClientConfirmation ends the IdP half of a client flow. The client gets
// its token only once the person in this browser confirms the sign-in on a
// page naming the device that asked for it, and enters their TOTP code when
// they have one: without that step a link to the real IdP, sent to someone
// with an SSO session there, signed them in on the sender's device, and the
// panel's second factor was never asked for.
func (s *Service) askClientConfirmation(w http.ResponseWriter, r *http.Request, st *store.OAuthState, prov *store.IdentityProvider, user *store.User) {
	ctx := r.Context()
	fail := func(fe *flowError) {
		_ = s.st.OAuthStates.Complete(ctx, st.ID, nil, fe.Msg)
		s.recordEvent(ctx, st, &user.ID, nil, user.Username, false, "oidc_"+fe.Code, r)
		s.page(w, r, http.StatusForbidden, fe.Msg)
	}
	enrolled, err := s.totpEnrolled(ctx, user.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "oidc: second factor", slog.Any("err", err))
		fail(errFailed)
		return
	}
	if !enrolled && s.emailFactor != nil {
		required, err := s.emailFactor(ctx, user)
		if err != nil {
			s.log.ErrorContext(ctx, "oidc: e-mail factor", slog.Any("err", err))
			fail(errFailed)
			return
		}
		if required {
			fail(errEmailFactor)
			return
		}
	}
	token, err := s.sealConfirm(st.ID, user.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "oidc: seal confirmation", slog.Any("err", err))
		fail(errFailed)
		return
	}
	s.log.InfoContext(ctx, "oidc client login awaiting confirmation", slog.String("provider", prov.Slug),
		slog.Int64("user_id", user.ID))
	s.confirmPage(w, r, http.StatusOK, st, user, token, enrolled, "")
}

// HandleConfirm serves POST /api/oidc/confirm, the confirmation form of a
// client flow: "approve" (with the TOTP code when enrolled) completes it,
// anything else cancels it.
func (s *Service) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.page(w, r, http.StatusBadRequest, errExpired.Msg)
		return
	}
	token := r.PostForm.Get("token")
	stateID, userID, ok := s.openConfirm(token)
	if !ok {
		s.page(w, r, http.StatusBadRequest, errExpired.Msg)
		return
	}
	st, err := s.st.OAuthStates.GetActiveByID(ctx, stateID)
	if err != nil || st.Flow != store.OAuthFlowClient || st.Action != store.OAuthLogin ||
		st.ResultUserID != nil || st.ResultError != store.OAuthStateProcessing {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "oidc confirm: load state", slog.Any("err", err))
		}
		s.page(w, r, http.StatusBadRequest, errExpired.Msg)
		return
	}
	user, err := s.st.Users.GetByID(ctx, userID)
	if err != nil || !user.IsActive() {
		_ = s.st.OAuthStates.Complete(ctx, st.ID, nil, errDisabled.Msg)
		s.page(w, r, http.StatusForbidden, errDisabled.Msg)
		return
	}
	if r.PostForm.Get("action") != "approve" {
		_ = s.st.OAuthStates.Complete(ctx, st.ID, nil, errCancelled.Msg)
		s.recordEvent(ctx, st, &user.ID, nil, user.Username, false, "oidc_"+errCancelled.Code, r)
		s.page(w, r, http.StatusOK, errCancelled.Msg)
		return
	}
	enrolled, err := s.totpEnrolled(ctx, user.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "oidc confirm: second factor", slog.Any("err", err))
		s.page(w, r, http.StatusInternalServerError, errFailed.Msg)
		return
	}
	if enrolled {
		if ok, _ := auth.ReserveSecondFactor(s.limiter, user.ID); !ok {
			s.confirmPage(w, r, http.StatusTooManyRequests, st, user, token, true, errTooMany.Msg)
			return
		}
		valid, err := s.secondFactor.Verify(ctx, user.ID, strings.TrimSpace(r.PostForm.Get("code")))
		if err != nil {
			s.log.ErrorContext(ctx, "oidc confirm: verify code", slog.Any("err", err))
			s.page(w, r, http.StatusInternalServerError, errFailed.Msg)
			return
		}
		if !valid {
			s.recordEvent(ctx, st, &user.ID, nil, user.Username, false, "totp_invalid", r)
			s.confirmPage(w, r, http.StatusUnauthorized, st, user, token, true, errCode.Msg)
			return
		}
		auth.ReleaseSecondFactor(s.limiter, user.ID)
	}
	if err := s.st.OAuthStates.Complete(ctx, st.ID, &user.ID, ""); err != nil {
		s.page(w, r, http.StatusBadRequest, errExpired.Msg)
		return
	}
	s.log.InfoContext(ctx, "oidc client login approved", slog.Int64("user_id", user.ID))
	s.page(w, r, http.StatusOK, "")
}

// confirmExpiry is when st stops accepting the confirmation (for the page).
func confirmExpiry(st *store.OAuthState, now time.Time) int {
	return max(0, int(st.ExpiresAt.Sub(now).Minutes()+0.5))
}
