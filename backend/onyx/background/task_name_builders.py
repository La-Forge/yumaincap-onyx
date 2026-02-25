from datetime import datetime

from onyx.configs.constants import OnyxCeleryTask


QUERY_HISTORY_TASK_NAME_PREFIX = OnyxCeleryTask.EXPORT_QUERY_HISTORY_TASK


def query_history_task_name(start: datetime, end: datetime) -> str:
    return f"{QUERY_HISTORY_TASK_NAME_PREFIX}_{start}_{end}"
