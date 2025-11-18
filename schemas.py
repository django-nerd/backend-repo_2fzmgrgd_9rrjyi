from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List

# Smart Study Schemas

class User(BaseModel):
    email: EmailStr = Field(..., description="Unique email for login")
    name: str = Field(..., description="Full name")
    password_hash: str = Field(..., description="Hashed password")

class Note(BaseModel):
    user_id: str = Field(..., description="Owner user id")
    title: str = Field(..., description="Note title")
    content_text: Optional[str] = Field(None, description="Extracted plain text content")
    file_type: Optional[str] = Field(None, description="Uploaded file type: pdf|image|text")
    summary: Optional[str] = Field(None, description="AI generated summary")

class Question(BaseModel):
    note_id: str = Field(..., description="Related note id")
    question: str
    options: List[str]
    answer_index: int

class QuizResult(BaseModel):
    user_id: str
    note_id: str
    score: int
    total: int
