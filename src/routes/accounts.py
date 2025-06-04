import logging
from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema
from schemas.accounts import (
    UserLoginRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    DetailResponse,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    UserLoginResponseSchema, PasswordResetCompleteRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )
    user_group = await db.scalar(
        select(
            UserGroupModel
        ).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )
    if not user_group:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user=new_user,
        )
        db.add(activation_token)

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    return new_user


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )
    try:
        token_obj = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(token_obj)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": DetailResponse}
    }
)
async def activate_account(
    request: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    """
    Activates a user's account using a valid activation token and email.
    """
    user = await db.scalar(
        select(UserModel).where(UserModel.email == request.email)
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == request.token
        )
    )

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    token_expiry_aware = activation_token.expires_at.replace(tzinfo=timezone.utc)

    if token_expiry_aware < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True
        db.add(user)
        await db.delete(activation_token)
        await db.commit()
        await db.refresh(user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        )

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {"model": MessageResponseSchema}
    }
)
async def password_reset(
    request: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    """
       Allows users to request a password reset token.
       Always returns a success message to prevent user enumeration.
       """
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == request.email)
        )

        if user and user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            )
            await db.flush()

            new_reset_token = PasswordResetTokenModel(
                user=user,
            )
            db.add(new_reset_token)

            await db.commit()

        return {"message": "If you are registered, you will receive an email with instructions."}

    except SQLAlchemyError:
        await db.rollback()

        return {"message": "If you are registered, you will receive an email with instructions."}
    except Exception as e:
        return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": DetailResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": DetailResponse}
    }
)
async def complete_password_reset(
    request: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    """
        Allows users to reset their password using a valid password reset token.
        """
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == request.email)
        )

        existing_token_for_user = None
        if user:
            existing_token_for_user = await db.scalar(
                select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            )

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        reset_token_from_request = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == request.token
            )
        )

        if not reset_token_from_request:
            if existing_token_for_user:
                await db.delete(existing_token_for_user)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        current_utc_time = datetime.now(timezone.utc)
        token_expires_at_aware = reset_token_from_request.expires_at.replace(tzinfo=timezone.utc)

        if token_expires_at_aware < current_utc_time:
            await db.delete(reset_token_from_request)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = request.password

        await db.delete(reset_token_from_request)
        db.add(user)

        await db.commit()
        await db.refresh(user)

        return {"message": "Password reset successfully."}

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": DetailResponse},
        status.HTTP_401_UNAUTHORIZED: {"model": DetailResponse},
        status.HTTP_404_NOT_FOUND: {"model": DetailResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": DetailResponse}
    }
)
async def refresh_access_token(
    request: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    """
       Allows users to refresh their access token by providing a valid refresh token.
       """
    decoded_token_payload = None
    try:
        decoded_token_payload = jwt_manager.decode_refresh_token(request.refresh_token)

    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token format or signature."
        )

    user_id = decoded_token_payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token payload: user_id missing."
        )

    try:
        db_refresh_token = await db.scalar(
            select(RefreshTokenModel).where(
                RefreshTokenModel.user_id == user_id,
                RefreshTokenModel.token == request.refresh_token
            )
        )

        if not db_refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        current_utc_time = datetime.now(timezone.utc)
        token_expires_at_aware = db_refresh_token.expires_at.replace(tzinfo=timezone.utc)

        if token_expires_at_aware < current_utc_time:
            await db.delete(db_refresh_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )

        user = await db.scalar(
            select(UserModel).where(UserModel.id == user_id)
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        new_access_token = jwt_manager.create_access_token(
            {"user_id": user.id}
        )

        return {"access_token": new_access_token}

    except HTTPException:
        raise
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while refreshing the token."
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred."
        )
