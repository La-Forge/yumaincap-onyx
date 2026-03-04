import datetime
from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import and_
from sqlalchemy import case
from sqlalchemy import cast
from sqlalchemy import Date
from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy.orm import Session

from onyx.configs.constants import MessageType
from onyx.db.models import ChatMessage
from onyx.db.models import ChatMessageFeedback
from onyx.db.models import ChatSession
from onyx.db.models import Persona
from onyx.db.models import User
from onyx.db.models import UserRole


def fetch_query_analytics(
    start: datetime.datetime,
    end: datetime.datetime,
    db_session: Session,
) -> Sequence[tuple[int, int, int, datetime.date]]:
    stmt = (
        select(
            func.count(ChatMessage.id),
            func.sum(case((ChatMessageFeedback.is_positive, 1), else_=0)),
            func.sum(
                case(
                    (ChatMessageFeedback.is_positive == False, 1), else_=0  # noqa: E712
                )
            ),
            cast(ChatMessage.time_sent, Date),
        )
        .join(
            ChatMessageFeedback,
            ChatMessageFeedback.chat_message_id == ChatMessage.id,
            isouter=True,
        )
        .where(
            ChatMessage.time_sent >= start,
        )
        .where(
            ChatMessage.time_sent <= end,
        )
        .where(ChatMessage.message_type == MessageType.ASSISTANT)
        .group_by(cast(ChatMessage.time_sent, Date))
        .order_by(cast(ChatMessage.time_sent, Date))
    )

    return db_session.execute(stmt).all()  # type: ignore


def fetch_per_user_query_analytics(
    start: datetime.datetime,
    end: datetime.datetime,
    db_session: Session,
) -> Sequence[tuple[int, int, int, datetime.date, UUID]]:
    stmt = (
        select(
            func.count(ChatMessage.id),
            func.sum(case((ChatMessageFeedback.is_positive, 1), else_=0)),
            func.sum(
                case(
                    (ChatMessageFeedback.is_positive == False, 1), else_=0  # noqa: E712
                )
            ),
            cast(ChatMessage.time_sent, Date),
            ChatSession.user_id,
        )
        .join(ChatSession, ChatSession.id == ChatMessage.chat_session_id)
        .join(
            ChatMessageFeedback,
            ChatMessageFeedback.chat_message_id == ChatMessage.id,
            isouter=True,
        )
        .where(
            ChatMessage.time_sent >= start,
        )
        .where(
            ChatMessage.time_sent <= end,
        )
        .where(ChatMessage.message_type == MessageType.ASSISTANT)
        .group_by(cast(ChatMessage.time_sent, Date), ChatSession.user_id)
        .order_by(cast(ChatMessage.time_sent, Date), ChatSession.user_id)
    )

    return db_session.execute(stmt).all()  # type: ignore


def fetch_onyxbot_analytics(
    start: datetime.datetime,
    end: datetime.datetime,
    db_session: Session,
) -> Sequence[tuple[int, int, datetime.date]]:
    subquery_first_ai_response = (
        db_session.query(
            ChatMessage.chat_session_id.label("chat_session_id"),
            func.min(ChatMessage.id).label("chat_message_id"),
        )
        .join(ChatSession, ChatSession.id == ChatMessage.chat_session_id)
        .where(
            ChatSession.time_created >= start,
            ChatSession.time_created <= end,
            ChatSession.onyxbot_flow.is_(True),
        )
        .where(
            ChatMessage.message_type == MessageType.ASSISTANT,
        )
        .group_by(ChatMessage.chat_session_id)
        .subquery()
    )

    subquery_last_feedback = (
        db_session.query(
            ChatMessageFeedback.chat_message_id.label("chat_message_id"),
            func.max(ChatMessageFeedback.id).label("max_feedback_id"),
        )
        .group_by(ChatMessageFeedback.chat_message_id)
        .subquery()
    )

    results = (
        db_session.query(
            func.count(ChatSession.id).label("total_sessions"),
            func.sum(
                case(
                    (
                        or_(
                            ChatMessageFeedback.is_positive.is_(False),
                            ChatMessageFeedback.required_followup.is_(True),
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("negative_answer"),
            cast(ChatSession.time_created, Date).label("session_date"),
        )
        .join(
            subquery_first_ai_response,
            ChatSession.id == subquery_first_ai_response.c.chat_session_id,
        )
        .outerjoin(
            subquery_last_feedback,
            subquery_first_ai_response.c.chat_message_id
            == subquery_last_feedback.c.chat_message_id,
        )
        .outerjoin(
            ChatMessageFeedback,
            ChatMessageFeedback.id == subquery_last_feedback.c.max_feedback_id,
        )
        .group_by(cast(ChatSession.time_created, Date))
        .order_by(cast(ChatSession.time_created, Date))
        .all()
    )

    return [tuple(row) for row in results]


def fetch_persona_message_analytics(
    db_session: Session,
    persona_id: int,
    start: datetime.datetime,
    end: datetime.datetime,
) -> list[tuple[int, datetime.date]]:
    query = (
        select(
            func.count(ChatMessage.id),
            cast(ChatMessage.time_sent, Date),
        )
        .join(
            ChatSession,
            ChatMessage.chat_session_id == ChatSession.id,
        )
        .where(
            ChatSession.persona_id == persona_id,
            ChatMessage.time_sent >= start,
            ChatMessage.time_sent <= end,
            ChatMessage.message_type == MessageType.ASSISTANT,
        )
        .group_by(cast(ChatMessage.time_sent, Date))
        .order_by(cast(ChatMessage.time_sent, Date))
    )

    return [tuple(row) for row in db_session.execute(query).all()]


def fetch_persona_unique_users(
    db_session: Session,
    persona_id: int,
    start: datetime.datetime,
    end: datetime.datetime,
) -> list[tuple[int, datetime.date]]:
    query = (
        select(
            func.count(func.distinct(ChatSession.user_id)),
            cast(ChatMessage.time_sent, Date),
        )
        .join(
            ChatSession,
            ChatMessage.chat_session_id == ChatSession.id,
        )
        .where(
            ChatSession.persona_id == persona_id,
            ChatMessage.time_sent >= start,
            ChatMessage.time_sent <= end,
            ChatMessage.message_type == MessageType.ASSISTANT,
        )
        .group_by(cast(ChatMessage.time_sent, Date))
        .order_by(cast(ChatMessage.time_sent, Date))
    )

    return [tuple(row) for row in db_session.execute(query).all()]


def fetch_assistant_message_analytics(
    db_session: Session,
    assistant_id: int,
    start: datetime.datetime,
    end: datetime.datetime,
) -> list[tuple[int, datetime.date]]:
    query = (
        select(
            func.count(ChatMessage.id),
            cast(ChatMessage.time_sent, Date),
        )
        .join(
            ChatSession,
            ChatMessage.chat_session_id == ChatSession.id,
        )
        .where(
            ChatSession.persona_id == assistant_id,
            ChatMessage.time_sent >= start,
            ChatMessage.time_sent <= end,
            ChatMessage.message_type == MessageType.ASSISTANT,
        )
        .group_by(cast(ChatMessage.time_sent, Date))
        .order_by(cast(ChatMessage.time_sent, Date))
    )

    return [tuple(row) for row in db_session.execute(query).all()]


def fetch_assistant_unique_users(
    db_session: Session,
    assistant_id: int,
    start: datetime.datetime,
    end: datetime.datetime,
) -> list[tuple[int, datetime.date]]:
    query = (
        select(
            func.count(func.distinct(ChatSession.user_id)),
            cast(ChatMessage.time_sent, Date),
        )
        .join(
            ChatSession,
            ChatMessage.chat_session_id == ChatSession.id,
        )
        .where(
            ChatSession.persona_id == assistant_id,
            ChatMessage.time_sent >= start,
            ChatMessage.time_sent <= end,
            ChatMessage.message_type == MessageType.ASSISTANT,
        )
        .group_by(cast(ChatMessage.time_sent, Date))
        .order_by(cast(ChatMessage.time_sent, Date))
    )

    return [tuple(row) for row in db_session.execute(query).all()]


def fetch_assistant_unique_users_total(
    db_session: Session,
    assistant_id: int,
    start: datetime.datetime,
    end: datetime.datetime,
) -> int:
    query = (
        select(func.count(func.distinct(ChatSession.user_id)))
        .select_from(ChatMessage)
        .join(
            ChatSession,
            ChatMessage.chat_session_id == ChatSession.id,
        )
        .where(
            ChatSession.persona_id == assistant_id,
            ChatMessage.time_sent >= start,
            ChatMessage.time_sent <= end,
            ChatMessage.message_type == MessageType.ASSISTANT,
        )
    )

    result = db_session.execute(query).scalar()
    return result if result else 0


def user_can_view_assistant_stats(
    db_session: Session, user: User | None, assistant_id: int
) -> bool:
    if user is None or user.role == UserRole.ADMIN:
        return True

    stmt = select(Persona).where(
        and_(Persona.id == assistant_id, Persona.user_id == user.id)
    )

    persona = db_session.execute(stmt).scalar_one_or_none()
    return persona is not None
