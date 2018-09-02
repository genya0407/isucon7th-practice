package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/binary"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
	"github.com/sevenNt/echo-pprof"
	"isubata/templates"
	"isubata/types"
)

const (
	avatarMaxBytes = 1 * 1024 * 1024
)

var (
	db            *sqlx.DB
	ErrBadReqeust = echo.NewHTTPError(http.StatusBadRequest)
)

type Renderer struct {
	templates *template.Template
}

func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

func init() {
	seedBuf := make([]byte, 8)
	crand.Read(seedBuf)
	rand.Seed(int64(binary.LittleEndian.Uint64(seedBuf)))

	db_host := os.Getenv("ISUBATA_DB_HOST")
	if db_host == "" {
		db_host = "127.0.0.1"
	}
	db_port := os.Getenv("ISUBATA_DB_PORT")
	if db_port == "" {
		db_port = "3306"
	}
	db_user := os.Getenv("ISUBATA_DB_USER")
	if db_user == "" {
		db_user = "root"
	}
	db_password := os.Getenv("ISUBATA_DB_PASSWORD")
	if db_password != "" {
		db_password = ":" + db_password
	}

	dsn := fmt.Sprintf("%s%s@tcp(%s:%s)/isubata?parseTime=true&loc=Local&charset=utf8mb4",
		db_user, db_password, db_host, db_port)

	log.Printf("Connecting to db: %q", dsn)
	db, _ = sqlx.Connect("mysql", dsn)
	for {
		err := db.Ping()
		if err == nil {
			break
		}
		log.Println(err)
		time.Sleep(time.Second * 3)
	}

	db.SetMaxOpenConns(20)
	db.SetConnMaxLifetime(5 * time.Minute)
	log.Printf("Succeeded to connect db.")
}

func getUser(userID int64) (*types.User, error) {
	u := types.User{}
	if err := db.Get(&u, "SELECT id, name, display_name, avatar_icon FROM user WHERE id = ?", userID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func addMessage(channelID, userID int64, content string) (int64, error) {
	res, err := db.Exec(
		"INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())",
		channelID, userID, content)
	if err != nil {
		return 0, err
	}

	go db.Exec("UPDATE channel SET cnt = cnt + 1 WHERE id = ?", channelID)

	return res.LastInsertId()
}

type Message struct {
	ID        int64     `db:"id"`
	ChannelID int64     `db:"channel_id"`
	UserID    int64     `db:"user_id"`
	Content   string    `db:"content"`
	CreatedAt time.Time `db:"created_at"`
}

func queryMessages(chanID, lastID int64) ([]Message, error) {
	msgs := []Message{}
	err := db.Select(&msgs, "SELECT * FROM message WHERE id > ? AND channel_id = ? ORDER BY id DESC LIMIT 100",
		lastID, chanID)
	return msgs, err
}

var sessToId = map[string]int64{}

func sessUserID(c echo.Context) int64 {
	cookie, err := c.Cookie("session")
	if err != nil {
		return 0
	}
	userID, ok := sessToId[cookie.Value]
	if ok {
		return userID
	}
	sess, _ := session.Get("session", c)
	if x, ok := sess.Values["user_id"]; ok {
		userID, _ = x.(int64)
	}
	sessToId[cookie.Value] = userID
	return userID
}

func sessSetUserID(c echo.Context, id int64) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   360000,
	}
	sess.Values["user_id"] = id
	sess.Save(c.Request(), c.Response())
}

func ensureLogin(c echo.Context) (*types.User, error) {
	var user *types.User
	var err error

	userID := sessUserID(c)
	if userID == 0 {
		goto redirect
	}

	user, err = getUser(userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		sess, _ := session.Get("session", c)
		delete(sess.Values, "user_id")
		sess.Save(c.Request(), c.Response())
		goto redirect
	}
	return user, nil

redirect:
	c.Redirect(http.StatusSeeOther, "/login")
	return nil, nil
}

const LettersAndDigits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	z := len(LettersAndDigits)

	for i := 0; i < n; i++ {
		b[i] = LettersAndDigits[rand.Intn(z)]
	}
	return string(b)
}

func register(name, password string) (int64, error) {
	salt := randomString(20)
	digest := fmt.Sprintf("%x", sha1.Sum([]byte(salt+password)))

	res, err := db.Exec(
		"INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at)"+
			" VALUES (?, ?, ?, ?, ?, NOW())",
		name, salt, digest, name, "default.png")
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// request handlers

func getInitialize(c echo.Context) error {
	db.MustExec("DELETE FROM user WHERE id > 1000")
	db.MustExec("DELETE FROM channel WHERE id > 10")
	db.MustExec("DELETE FROM message WHERE id > 10000")
	db.MustExec("UPDATE channel as c LEFT JOIN ( SELECT m.channel_id, COUNT(m.id) as msg_cnt FROM message as m GROUP BY m.channel_id) as m_c ON c.id = m_c.channel_id SET c.cnt = COALESCE(m_c.msg_cnt, 0)")
	db.MustExec("DELETE FROM haveread")
	return c.String(204, "")
}

func getIndex(c echo.Context) error {
	userID := sessUserID(c)
	if userID != 0 {
		return c.Redirect(http.StatusSeeOther, "/channel/1")
	}

	return c.Render(http.StatusOK, "index", map[string]interface{}{
		"ChannelID": nil,
	})
}

func getChannel(c echo.Context) error {
	user, err := ensureLogin(c)
	if user == nil {
		return err
	}
	cID, err := strconv.Atoi(c.Param("channel_id"))
	if err != nil {
		return err
	}
	channels := []types.ChannelInfo{}
	err = db.Select(&channels, "SELECT * FROM channel ORDER BY id")
	if err != nil {
		return err
	}

	var desc string
	for _, ch := range channels {
		if ch.ID == int64(cID) {
			desc = ch.Description
			break
		}
	}
	return c.Render(http.StatusOK, "channel", map[string]interface{}{
		"ChannelID":   cID,
		"Channels":    channels,
		"User":        user,
		"Description": desc,
	})
}

func getRegister(c echo.Context) error {
	return c.Render(http.StatusOK, "register", map[string]interface{}{
		"ChannelID": 0,
		"Channels":  []types.ChannelInfo{},
		"User":      nil,
	})
}

func postRegister(c echo.Context) error {
	name := c.FormValue("name")
	pw := c.FormValue("password")
	if name == "" || pw == "" {
		return ErrBadReqeust
	}
	userID, err := register(name, pw)
	if err != nil {
		if merr, ok := err.(*mysql.MySQLError); ok {
			if merr.Number == 1062 { // Duplicate entry xxxx for key zzzz
				return c.NoContent(http.StatusConflict)
			}
		}
		return err
	}
	sessSetUserID(c, userID)
	return c.Redirect(http.StatusSeeOther, "/")
}

func getLogin(c echo.Context) error {
	return c.Render(http.StatusOK, "login", map[string]interface{}{
		"ChannelID": 0,
		"Channels":  []types.ChannelInfo{},
		"User":      nil,
	})
}

var users map[string]types.User = map[string]types.User{}

func queryUser(name string) (types.User, error) {
	var user types.User

	user, ok := users[name]
	if ok {
		return user, nil
	}

	err := db.Get(&user, "SELECT salt, password, id FROM user WHERE name = ?", name)
	if err == nil {
		users[name] = user
	}

	return user, err
}

func postLogin(c echo.Context) error {
	name := c.FormValue("name")
	pw := c.FormValue("password")
	if name == "" || pw == "" {
		return ErrBadReqeust
	}

	user, err := queryUser(name)
	if err == sql.ErrNoRows {
		return echo.ErrForbidden
	} else if err != nil {
		return err
	}

	digest := fmt.Sprintf("%x", sha1.Sum([]byte(user.Salt+pw)))
	if digest != user.Password {
		return echo.ErrForbidden
	}
	sessSetUserID(c, user.ID)
	return c.Redirect(http.StatusSeeOther, "/")
}

func getLogout(c echo.Context) error {
	sess, _ := session.Get("session", c)
	delete(sess.Values, "user_id")
	sess.Save(c.Request(), c.Response())
	return c.Redirect(http.StatusSeeOther, "/")
}

func postMessage(c echo.Context) error {
	userID := sessUserID(c)

	message := c.FormValue("message")
	if message == "" {
		return echo.ErrForbidden
	}

	var chanID int64
	if x, err := strconv.Atoi(c.FormValue("channel_id")); err != nil {
		return echo.ErrForbidden
	} else {
		chanID = int64(x)
	}

	go func() {
		addMessage(chanID, userID, message)
	}()

	return c.NoContent(204)
}

func jsonifyMessage(m Message) (map[string]interface{}, error) {
	u := types.User{}
	err := db.Get(&u, "SELECT name, display_name, avatar_icon FROM user WHERE id = ?",
		m.UserID)
	if err != nil {
		return nil, err
	}

	r := make(map[string]interface{})
	r["id"] = m.ID
	r["user"] = u
	r["date"] = m.CreatedAt.Format("2006/01/02 15:04:05")
	r["content"] = m.Content
	return r, nil
}

func queryMessagesWithUser(chanID, lastID int64) ([]types.MessageWithUser, error) {
	msgs := []types.MessageWithUser{}
	err := db.Select(&msgs,
		"SELECT m.id as msg_id, m.content, m.created_at, u.name, u.display_name, u.avatar_icon FROM message as m JOIN user as u ON m.user_id = u.id WHERE m.channel_id = ? AND m.id > ? ORDER BY m.id DESC LIMIT 100",
		chanID, lastID)
	if err != nil {
		return nil, err
	}
	return msgs, nil
}

func jsonfyMessagesWithUser(msgs []types.MessageWithUser) []map[string]interface{} {
	rs := make([]map[string]interface{}, 0)
	for _, msg := range msgs {
		u := types.User{
			Name:        msg.UserName,
			DisplayName: msg.UserDisplayName,
			AvatarIcon:  msg.UserAvatarIcon,
		}
		r := make(map[string]interface{})
		r["id"] = msg.MessageID
		r["user"] = u
		r["date"] = msg.MessageCreatedAt.Format("2006/01/02 15:04:05")
		r["content"] = msg.MessageContent
		rs = append(rs, r)
	}
	return rs
}

func getMessage(c echo.Context) error {
	userID := sessUserID(c)
	if userID == 0 {
		return c.NoContent(http.StatusForbidden)
	}

	chanID, err := strconv.ParseInt(c.QueryParam("channel_id"), 10, 64)
	if err != nil {
		return err
	}
	lastID, err := strconv.ParseInt(c.QueryParam("last_message_id"), 10, 64)
	if err != nil {
		return err
	}

	messages, err := queryMessagesWithUser(chanID, lastID)
	if err != nil {
		return err
	}

	go func() {
		if len(messages) > 0 {
			db.Exec("INSERT INTO haveread (user_id, channel_id, read_count, updated_at, created_at)"+
				" VALUES (?, ?, (SELECT cnt FROM channel WHERE id = ? LIMIT 1), NOW(), NOW())"+
				" ON DUPLICATE KEY UPDATE read_count = read_count + ?, updated_at = NOW()",
				userID, chanID, chanID, len(messages))
		}
	}()

	reversed := []types.MessageWithUser{}
	for i := len(messages) - 1; i >= 0; i-- {
		reversed = append(reversed, messages[i])
	}
	marshaler := templates.MessageMarshaler{Msgs: reversed}
	var buf bytes.Buffer
	marshaler.WriteJSON(&buf)

	return c.JSONBlob(http.StatusOK, buf.Bytes())
}

var lastFetchedAtByUser = map[int64]time.Time{}

func fetchUnread(c echo.Context) error {
	userID := sessUserID(c)
	if userID == 0 {
		return c.NoContent(http.StatusForbidden)
	}

	type Count struct {
		ChannelID int64 `db:"channel_id"`
		Cnt       int64 `db:"cnt"`
	}

	time.Sleep(time.Second)

	lastFetchedAt, ok := lastFetchedAtByUser[userID]
	if ok {
		now := time.Now()
		shouldFetchedAt := lastFetchedAt.Add(time.Duration(8) * time.Second)
		if shouldFetchedAt.Before(now) {
			// immediate return
		} else {
			// sleep untile `shouldFetchedAt`
			time.Sleep(shouldFetchedAt.Sub(now))
		}
	}

	counts := []Count{}
	err := db.Select(&counts,
		"SELECT c.id as channel_id, (c.cnt - COALESCE(h.read_count, 0)) as cnt FROM channel as c LEFT OUTER JOIN haveread as h ON c.id = h.channel_id")
	if err != nil {
		return err
	}

	resp := []map[string]interface{}{}
	for _, c := range counts {
		r := map[string]interface{}{
			"channel_id": c.ChannelID,
			"unread":     c.Cnt}
		resp = append(resp, r)
	}

	lastFetchedAtByUser[userID] = time.Now()

	return c.JSON(http.StatusOK, resp)
}

func getHistory(c echo.Context) error {
	chID, err := strconv.ParseInt(c.Param("channel_id"), 10, 64)
	if err != nil || chID <= 0 {
		return ErrBadReqeust
	}

	type UserResult struct {
		User *types.User
		err  error
	}
	userCh := make(chan UserResult)
	go func() {
		user, err := ensureLogin(c)
		userCh <- UserResult { User: user, err: err }
		close(userCh)
	}()

	var page int64
	pageStr := c.QueryParam("page")
	if pageStr == "" {
		page = 1
	} else {
		page, err = strconv.ParseInt(pageStr, 10, 64)
		if err != nil || page < 1 {
			return ErrBadReqeust
		}
	}

	type CntResult struct {
		cnt int64
		err error
	}
	cntCh := make(chan CntResult)
	const N = 20
	go func() {
		var cnt int64
		err = db.Get(&cnt, "SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?", chID)
		cntCh <- CntResult { cnt: cnt, err: err }
		close(cntCh)
	}()

	type MessageResult struct {
		msgs []types.MessageWithUser
		err  error
	}
	msgCh := make(chan MessageResult)
	go func() {
		messages := []types.MessageWithUser{}
		err = db.Select(&messages,
			"SELECT m.id as msg_id, m.content, m.created_at, u.name, u.display_name, u.avatar_icon FROM message as m JOIN user as u ON m.user_id = u.id WHERE m.channel_id = ? ORDER BY m.id DESC LIMIT ? OFFSET ?",
			chID, N, (page-1)*N)
		msgCh <- MessageResult { msgs: messages, err: err }
		close(msgCh)
	}()

	channels := []types.ChannelInfo{}
	err = db.Select(&channels, "SELECT id, name FROM channel ORDER BY id")
	if err != nil {
		return err
	}

	userResult := <- userCh
	if userResult.User == nil {
		return userResult.err
	}

	cntResult := <- cntCh
	if cntResult.err != nil {
		return cntResult.err
	}
	maxPage := int64(cntResult.cnt+N-1) / N
	if maxPage == 0 {
		maxPage = 1
	}
	if page > maxPage {
		return ErrBadReqeust
	}

	msgResult := <- msgCh
	if msgResult.err != nil {
		return msgResult.err
	}
	messages := msgResult.msgs
	reversed := make([]types.MessageWithUser, len(messages))
	for i := len(messages) - 1; i >= 0; i-- {
		reversed[len(messages) - i - 1] = messages[i]
	}

	view := templates.HistoryView{
		ChannelID: chID,
		Channels:  channels,
		Messages:  reversed,
		MaxPage:   maxPage,
		Page:      page,
		User:      *userResult.User,
	}
	var buf bytes.Buffer
	view.WriteHTML(&buf)

	return c.HTMLBlob(http.StatusOK, buf.Bytes())
}

type GetProfileDTO struct {
	ChannelID   int64
	Channels    []types.ChannelInfo
	User        types.User
	Other       types.User
	SelfProfile bool
}

func getProfile(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	channels := []types.ChannelInfo{}
	err = db.Select(&channels, "SELECT * FROM channel ORDER BY id")
	if err != nil {
		return err
	}

	userName := c.Param("user_name")
	var other types.User
	err = db.Get(&other, "SELECT * FROM user WHERE name = ?", userName)
	if err == sql.ErrNoRows {
		return echo.ErrNotFound
	}
	if err != nil {
		return err
	}

	return c.Render(http.StatusOK, "profile", GetProfileDTO {
		ChannelID:   0,
		Channels:    channels,
		User:        *self,
		Other:       other,
		SelfProfile: self.ID == other.ID,
	})
}

func getAddChannel(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	channels := []types.ChannelInfo{}
	err = db.Select(&channels, "SELECT * FROM channel ORDER BY id")
	if err != nil {
		return err
	}

	return c.Render(http.StatusOK, "add_channel", map[string]interface{}{
		"ChannelID": 0,
		"Channels":  channels,
		"User":      self,
	})
}

func postAddChannel(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	name := c.FormValue("name")
	desc := c.FormValue("description")
	if name == "" || desc == "" {
		return ErrBadReqeust
	}

	res, err := db.Exec(
		"INSERT INTO channel (name, description, updated_at, created_at, cnt) VALUES (?, ?, NOW(), NOW(), 0)",
		name, desc)
	if err != nil {
		return err
	}
	lastID, _ := res.LastInsertId()
	return c.Redirect(http.StatusSeeOther,
		fmt.Sprintf("/channel/%v", lastID))
}

func postProfile(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	go func() {
		if name := c.FormValue("display_name"); name != "" {
			db.Exec("UPDATE user SET display_name = ? WHERE id = ?", name, self.ID)
		}
	}()

	avatarName := ""
	var avatarData []byte

	fh, err := c.FormFile("avatar_icon")
	if err == http.ErrMissingFile {
		// no file upload
	} else if err != nil {
		return err
	} else {
		dotPos := strings.LastIndexByte(fh.Filename, '.')
		if dotPos < 0 {
			return ErrBadReqeust
		}
		ext := fh.Filename[dotPos:]
		switch ext {
		case ".jpg", ".jpeg", ".png", ".gif":
			break
		default:
			return ErrBadReqeust
		}

		file, err := fh.Open()
		if err != nil {
			return err
		}
		avatarData, _ = ioutil.ReadAll(file)
		file.Close()

		if len(avatarData) > avatarMaxBytes {
			return ErrBadReqeust
		}

		avatarName = fmt.Sprintf("%x%s", sha1.Sum(avatarData), ext)
	}

	if avatarName != "" && len(avatarData) > 0 {
		file, _ := os.Create("/home/isucon/isubata/webapp/autofs/icons/" + avatarName)
		defer file.Close()
		file.Write(avatarData)

		db.Exec("UPDATE user SET avatar_icon = ? WHERE id = ?", avatarName, self.ID)
	}

	return c.Redirect(http.StatusSeeOther, "/")
}

func tAdd(a, b int64) int64 {
	return a + b
}

func tRange(a, b int64) []int64 {
	r := make([]int64, b-a+1)
	for i := int64(0); i <= (b - a); i++ {
		r[i] = a + i
	}
	return r
}

func main() {
	e := echo.New()
	funcs := template.FuncMap{
		"add":    tAdd,
		"xrange": tRange,
	}
	e.Renderer = &Renderer{
		templates: template.Must(template.New("").Funcs(funcs).ParseGlob("views/*.html")),
	}
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secretonymoris"))))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "request:\"${method} ${uri}\" status:${status} latency:${latency} (${latency_human}) bytes:${bytes_out}\n",
	}))
	e.Use(middleware.Static("../public"))

	e.GET("/initialize", getInitialize)
	e.GET("/", getIndex)
	e.GET("/register", getRegister)
	e.POST("/register", postRegister)
	e.GET("/login", getLogin)
	e.POST("/login", postLogin)
	e.GET("/logout", getLogout)

	e.GET("/channel/:channel_id", getChannel)
	e.GET("/message", getMessage)
	e.POST("/message", postMessage)
	e.GET("/fetch", fetchUnread)
	e.GET("/history/:channel_id", getHistory)

	e.GET("/profile/:user_name", getProfile)
	e.POST("/profile", postProfile)

	e.GET("add_channel", getAddChannel)
	e.POST("add_channel", postAddChannel)

	echopprof.Wrap(e)

	e.Start(":5000")
}
