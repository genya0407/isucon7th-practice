package types

import   "time"

type MessageWithUser struct {
    UserName        string `db:"name"`
    UserDisplayName string `db:"display_name"`
    UserAvatarIcon  string `db:"avatar_icon"`

    MessageID        int64     `db:"msg_id"`
    MessageContent   string    `db:"content"`
    MessageCreatedAt time.Time `db:"created_at"`
}

type ChannelInfo struct {
    ID          int64     `db:"id"`
    Name        string    `db:"name"`
    Description string    `db:"description"`
    Cnt         int64      `db:"cnt"`
    UpdatedAt   time.Time `db:"updated_at"`
    CreatedAt   time.Time `db:"created_at"`
}


type User struct {
    ID          int64     `json:"-" db:"id"`
    Name        string    `json:"name" db:"name"`
    Salt        string    `json:"-" db:"salt"`
    Password    string    `json:"-" db:"password"`
    DisplayName string    `json:"display_name" db:"display_name"`
    AvatarIcon  string    `json:"avatar_icon" db:"avatar_icon"`
    CreatedAt   time.Time `json:"-" db:"created_at"`
}
