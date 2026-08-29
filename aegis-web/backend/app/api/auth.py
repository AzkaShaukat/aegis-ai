"""app/api/auth.py — Authentication routes with detailed error logging."""
from __future__ import annotations
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.auth import (
    AccessTokenResponse, ForgotPasswordRequest, LoginRequest,
    MessageResponse, RefreshRequest, RegisterRequest, RegisterResponse,
    ResendVerificationRequest, ResetPasswordRequest, TokenResponse,
    UserMeResponse, VerifyEmailRequest,
)
from app.services import auth_service
from app.services.auth_service import AuthError

settings = get_settings()
router   = APIRouter(prefix="/api/auth", tags=["auth"])
logger   = logging.getLogger(__name__)


def _http(code: int, msg: str) -> HTTPException:
    return HTTPException(status_code=code, detail=msg)


# ── Register ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Create a new user account."""
    logger.info("Register attempt: email=%s", req.email)
    try:
        user = await auth_service.create_user(
            db, req.email, req.password, req.display_name
        )
        await db.commit()
        await db.refresh(user)  # ensure all fields loaded after commit

        if settings.email_enabled and not user.email_verified:
            try:
                await auth_service.send_verification_for(user)
                msg = (
                    f"Account created! A verification email has been sent to {user.email}. "
                    "Please click the link in the email to activate your account."
                )
            except Exception as email_err:
                logger.error("Failed to send verification email: %s", email_err)
                msg = (
                    "Account created but we couldn't send the verification email. "
                    "Please use 'Resend verification' on the login page."
                )
        else:
            msg = "Account created successfully! You can now sign in."

        logger.info("Register success: email=%s verified=%s", user.email, user.email_verified)
        return RegisterResponse(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            email_verified=user.email_verified,
            created_at=user.created_at,
            message=msg,
        )

    except AuthError as e:
        logger.warning("Register AuthError for %s: %s", req.email, e)
        raise _http(status.HTTP_409_CONFLICT, str(e))

    except Exception as e:
        # Catch-all: log the full exception so we can see the real cause
        logger.error("Register UNEXPECTED error for %s: %s", req.email, e, exc_info=True)
        await db.rollback()
        raise _http(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Registration failed: {type(e).__name__}: {e}"
        )


# ── Verify email ──────────────────────────────────────────────────────────────

@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(req: VerifyEmailRequest, db: AsyncSession = Depends(get_db)):
    try:
        user = await auth_service.verify_email(db, req.token)
        await db.commit()
        try:
            from app.services.email_service import send_welcome_email
            await send_welcome_email(user.email, user.display_name)
        except Exception:
            pass  # welcome email failure is not critical
        return MessageResponse(message="Email verified! You can now sign in.")
    except AuthError as e:
        raise _http(status.HTTP_400_BAD_REQUEST, str(e))


# ── Resend verification ───────────────────────────────────────────────────────

@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(req: ResendVerificationRequest, db: AsyncSession = Depends(get_db)):
    await auth_service.resend_verification(db, req.email)
    return MessageResponse(
        message="If your account exists and is unverified, a new verification email has been sent."
    )


# ── Login ─────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    logger.info("Login attempt: email=%s", req.email)
    try:
        user   = await auth_service.authenticate_user(db, req.email, req.password)
        tokens = await auth_service.issue_tokens(db, user)
        await db.commit()
        logger.info("Login success: email=%s", req.email)
        return tokens
    except AuthError as e:
        logger.warning("Login failed for %s: %s", req.email, e)
        raise _http(status.HTTP_401_UNAUTHORIZED, str(e))
    except Exception as e:
        logger.error("Login unexpected error for %s: %s", req.email, e, exc_info=True)
        raise _http(status.HTTP_500_INTERNAL_SERVER_ERROR, f"Login error: {e}")


# ── Refresh ───────────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    tokens = await auth_service.refresh_access_token(db, req.refresh_token)
    if not tokens:
        raise _http(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token.")
    await db.commit()
    return {"access_token": tokens["access_token"], "token_type": "bearer", "expires_in": tokens["expires_in"]}


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout", status_code=204)
async def logout(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    await auth_service.revoke_refresh_token(db, req.refresh_token)
    await db.commit()


# ── Me ────────────────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserMeResponse)
async def me(current_user: User = Depends(get_current_user)):
    return current_user


# ── Forgot password ───────────────────────────────────────────────────────────

@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(req: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    await auth_service.send_password_reset(db, req.email)
    return MessageResponse(
        message="If an account with this email exists, a password reset link has been sent."
    )


# ── Reset password ────────────────────────────────────────────────────────────

@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(req: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    try:
        await auth_service.reset_password(db, req.token, req.new_password)
        await db.commit()
        return MessageResponse(message="Password updated successfully. You can now sign in.")
    except AuthError as e:
        raise _http(status.HTTP_400_BAD_REQUEST, str(e))
