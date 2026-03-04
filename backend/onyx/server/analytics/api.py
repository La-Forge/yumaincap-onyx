import datetime
from collections import defaultdict
from typing import List

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from onyx.db.analytics import fetch_assistant_message_analytics
from onyx.db.analytics import fetch_assistant_unique_users
from onyx.db.analytics import fetch_assistant_unique_users_total
from onyx.db.analytics import fetch_onyxbot_analytics
from onyx.db.analytics import fetch_per_user_query_analytics
from onyx.db.analytics import fetch_persona_message_analytics
from onyx.db.analytics import fetch_persona_unique_users
from onyx.db.analytics import fetch_query_analytics
from onyx.db.analytics import user_can_view_assistant_stats
from onyx.auth.users import current_admin_user
from onyx.auth.users import current_user
from onyx.configs.constants import PUBLIC_API_TAGS
from onyx.db.engine.sql_engine import get_session
from onyx.db.models import User

router = APIRouter(prefix="/analytics", tags=PUBLIC_API_TAGS)


_DEFAULT_LOOKBACK_DAYS = 30


class QueryAnalyticsResponse(BaseModel):
    total_queries: int
    total_likes: int
    total_dislikes: int
    date: datetime.date


@router.get("/admin/query")
def get_query_analytics(
    start: datetime.datetime | None = None,
    end: datetime.datetime | None = None,
    _: User | None = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> list[QueryAnalyticsResponse]:
    daily_query_usage_info = fetch_query_analytics(
        start=start
        or (
            datetime.datetime.utcnow() - datetime.timedelta(days=_DEFAULT_LOOKBACK_DAYS)
        ),
        end=end or datetime.datetime.utcnow(),
        db_session=db_session,
    )
    return [
        QueryAnalyticsResponse(
            total_queries=total_queries,
            total_likes=total_likes,
            total_dislikes=total_dislikes,
            date=date,
        )
        for total_queries, total_likes, total_dislikes, date in daily_query_usage_info
    ]


class UserAnalyticsResponse(BaseModel):
    total_active_users: int
    date: datetime.date


@router.get("/admin/user")
def get_user_analytics(
    start: datetime.datetime | None = None,
    end: datetime.datetime | None = None,
    _: User | None = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> list[UserAnalyticsResponse]:
    daily_query_usage_info_per_user = fetch_per_user_query_analytics(
        start=start
        or (
            datetime.datetime.utcnow() - datetime.timedelta(days=_DEFAULT_LOOKBACK_DAYS)
        ),
        end=end or datetime.datetime.utcnow(),
        db_session=db_session,
    )

    user_analytics: dict[datetime.date, int] = defaultdict(int)
    for __, ___, ____, date, _____ in daily_query_usage_info_per_user:
        user_analytics[date] += 1
    return [
        UserAnalyticsResponse(
            total_active_users=cnt,
            date=date,
        )
        for date, cnt in user_analytics.items()
    ]


class OnyxbotAnalyticsResponse(BaseModel):
    total_queries: int
    auto_resolved: int
    date: datetime.date


@router.get("/admin/onyxbot")
def get_onyxbot_analytics(
    start: datetime.datetime | None = None,
    end: datetime.datetime | None = None,
    _: User | None = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> list[OnyxbotAnalyticsResponse]:
    daily_onyxbot_info = fetch_onyxbot_analytics(
        start=start
        or (
            datetime.datetime.utcnow() - datetime.timedelta(days=_DEFAULT_LOOKBACK_DAYS)
        ),
        end=end or datetime.datetime.utcnow(),
        db_session=db_session,
    )

    return [
        OnyxbotAnalyticsResponse(
            total_queries=total_queries,
            auto_resolved=max(0, total_queries - total_negatives),
            date=date,
        )
        for total_queries, total_negatives, date in daily_onyxbot_info
    ]


class PersonaMessageAnalyticsResponse(BaseModel):
    total_messages: int
    date: datetime.date
    persona_id: int


@router.get("/admin/persona/messages")
def get_persona_messages(
    persona_id: int,
    start: datetime.datetime | None = None,
    end: datetime.datetime | None = None,
    _: User | None = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> list[PersonaMessageAnalyticsResponse]:
    start = start or (
        datetime.datetime.utcnow() - datetime.timedelta(days=_DEFAULT_LOOKBACK_DAYS)
    )
    end = end or datetime.datetime.utcnow()

    return [
        PersonaMessageAnalyticsResponse(
            total_messages=count,
            date=date,
            persona_id=persona_id,
        )
        for count, date in fetch_persona_message_analytics(
            db_session=db_session,
            persona_id=persona_id,
            start=start,
            end=end,
        )
    ]


class PersonaUniqueUsersResponse(BaseModel):
    unique_users: int
    date: datetime.date
    persona_id: int


@router.get("/admin/persona/unique-users")
def get_persona_unique_users(
    persona_id: int,
    start: datetime.datetime,
    end: datetime.datetime,
    _: User | None = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> list[PersonaUniqueUsersResponse]:
    return [
        PersonaUniqueUsersResponse(
            unique_users=count,
            date=date,
            persona_id=persona_id,
        )
        for count, date in fetch_persona_unique_users(
            db_session=db_session,
            persona_id=persona_id,
            start=start,
            end=end,
        )
    ]


class AssistantDailyUsageResponse(BaseModel):
    date: datetime.date
    total_messages: int
    total_unique_users: int


class AssistantStatsResponse(BaseModel):
    daily_stats: List[AssistantDailyUsageResponse]
    total_messages: int
    total_unique_users: int


@router.get("/assistant/{assistant_id}/stats")
def get_assistant_stats(
    assistant_id: int,
    start: datetime.datetime | None = None,
    end: datetime.datetime | None = None,
    user: User | None = Depends(current_user),
    db_session: Session = Depends(get_session),
) -> AssistantStatsResponse:
    start = start or (
        datetime.datetime.utcnow() - datetime.timedelta(days=_DEFAULT_LOOKBACK_DAYS)
    )
    end = end or datetime.datetime.utcnow()

    if not user_can_view_assistant_stats(db_session, user, assistant_id):
        raise HTTPException(
            status_code=403, detail="Not allowed to access this assistant's stats."
        )

    messages_data = fetch_assistant_message_analytics(
        db_session, assistant_id, start, end
    )
    unique_users_data = fetch_assistant_unique_users(
        db_session, assistant_id, start, end
    )

    daily_messages_map = {date: count for count, date in messages_data}
    daily_unique_users_map = {date: count for count, date in unique_users_data}
    all_dates = set(daily_messages_map.keys()) | set(daily_unique_users_map.keys())

    daily_results: list[AssistantDailyUsageResponse] = []
    for date in sorted(all_dates):
        daily_results.append(
            AssistantDailyUsageResponse(
                date=date,
                total_messages=daily_messages_map.get(date, 0),
                total_unique_users=daily_unique_users_map.get(date, 0),
            )
        )

    total_msgs = sum(d.total_messages for d in daily_results)
    total_users = fetch_assistant_unique_users_total(
        db_session, assistant_id, start, end
    )

    return AssistantStatsResponse(
        daily_stats=daily_results,
        total_messages=total_msgs,
        total_unique_users=total_users,
    )
