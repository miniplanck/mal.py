from typing import Literal


IMAGE_SIZE = Literal["medium", "large"]
NSFW = Literal["white", "gray", "black"]
ANIME_STATUS = Literal["finished_airing", "currently_airing", "not_yet_aired"]

USER_LIST_SORT = Literal[
    "list_score", "list_updated_at", "anime_title", "anime_start_date", "anime_id"
]
USER_ANIME_STATUS = Literal[
    "watching", "completed", "on_hold", "dropped", "plan_to_watch"
]

SEASONAL_LIST_SORT = Literal[
    "anime_score", "anime_num_list_users"
]
SEASONS = Literal[
    "winter", "spring", "summer", "fall"
]

MEDIA_TYPE = Literal["tv", "movie", "ova", "special", "ona", "music", "unknown"]
ANIME_SOURCE = Literal[
    "original",
    "manga",
    "4_koma_manga",
    "web_manga",
    "digital_manga",
    "novel",
    "light_novel",
    "visual_novel",
    "game",
    "card_game",
    "book",
    "picture_book",
    "radio",
    "music",
]

ANIME_RATING = Literal["g", "pg", "pg_13", "r", "r+", "rx"]
RELATION_TYPE = Literal[
    "sequel",
    "prequel",
    "alternative_setting",
    "alternative_version",
    "side_story",
    "parent_story",
    "summary",
    "full_story",
]
