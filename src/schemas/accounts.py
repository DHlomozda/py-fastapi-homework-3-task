from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from database import accounts_validators


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, email):
        return email.lower()


class UserRegistrationResponseSchema(UserBase):
    id: int


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class DetailResponse(BaseModel):
    detail: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
