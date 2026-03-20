package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type WithdrawAccountRequest struct {
	Password string `json:"password"`
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}

type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type PostListResponse struct {
	Posts []PostView `json:"posts"`
}

type PostResponse struct {
	Post PostView `json:"post"`
}

type DepositRequest struct {
	Amount int64 `json:"amount"`
}

type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}

type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}

type SessionStore struct {
	tokens map[string]User
}

func main() {
	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()
	registerStaticRoutes(router)

	auth := router.Group("/api/auth")
	{
		db, err := sql.Open("sqlite", "./app.db")
		if err != nil {
			panic(err)
		}
		defer db.Close()
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}
			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			_, err = tx.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, email TEXT, phone TEXT, password TEXT)")
			if err != nil {
				c.JSON(500, gin.H{"err": "테이블 생성 실패"})
			}
			defer tx.Rollback()
			_, err = tx.Exec("INSERT INTO users (username, name, email, phone, password) VALUES (?, ?, ?, ?, ?)", request.Username, request.Name, request.Email, request.Phone, request.Password)
			if err != nil {
				c.JSON(500, gin.H{"err": "사용자 생성 실패"})
				return
			}
			err = tx.Commit()
			if err != nil {
				c.JSON(500, gin.H{"err": "커밋 실패"})
				return
			}
		})

		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			user, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok || user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}

			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 60*60*8, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
			})
		})

		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
		})

		auth.POST("/withdraw", func(c *gin.Context) { //회원 탈퇴는 로그인한 이후에만 가능
			var request WithdrawAccountRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}
			token := tokenFromRequest(c) //로그인한 사용자의 토큰
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			sessions.delete(token)
			clearAuthorizationCookie(c)
			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			_, err = tx.Exec("DELETE FROM users WHERE password=?", request.Password)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete account"})
				return
			}
			err = tx.Commit()
			if err != nil {
				c.JSON(500, gin.H{"err": "커밋 실패"})
				return
			}
		})
	}

	protected := router.Group("/api")
	{
		db, err := sql.Open("sqlite", "./app.db")
		if err != nil {
			panic(err)
		}
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		protected.POST("/banking/deposit", func(c *gin.Context) { //입금
			var request DepositRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, balance INTEGER)`)
			if err != nil {
				c.JSON(500, gin.H{"err": "테이블 생성 실패"})
				return
			}
			defer tx.Rollback()
			_, err = tx.Exec(`INSERT INTO accounts (id, balance) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET balance = balance + ?`, user.ID, request.Amount, request.Amount)
			if err != nil {
				c.JSON(500, gin.H{"err": "입금 실패"})
				return
			}
			err = tx.Commit()
			if err != nil {
				c.JSON(500, gin.H{"err": "커밋 실패"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"amount": request.Amount,
			})
		})

		protected.POST("/banking/withdraw", func(c *gin.Context) { //출금
			var request BalanceWithdrawRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			_, err = tx.Exec(`UPDATE accounts SET balance = balance - ? WHERE id = ?`, request.Amount, user.ID)
			if err != nil {
				c.JSON(500, gin.H{"err": "출금 실패"})
				return
			}
			err = tx.Commit()
			if err != nil {
				c.JSON(500, gin.H{"err": "커밋 실패"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"amount": request.Amount,
			})
		})

		protected.POST("/banking/transfer", func(c *gin.Context) { //송금
			var request TransferRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			_, err = tx.Exec(`UPDATE accounts SET balance = balance - ? WHERE id = ?`, request.Amount, user.ID)
			if err != nil {
				c.JSON(500, gin.H{"err": "송금 실패"})
				return
			}
			defer tx.Rollback()
			_, err = tx.Exec(`UPDATE accounts SET balance = balance + ? WHERE id = (SELECT id FROM users WHERE username = ?)`, request.Amount, request.ToUsername)
			if err != nil {
				c.JSON(500, gin.H{"err": "송금 실패"})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"target": request.ToUsername,
				"amount": request.Amount,
			})
		})

		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			db, err := sql.Open("sqlite", "./app.db")
			if err != nil {
				c.JSON(500, gin.H{"err": "db 연결 실패"})
				return
			}
			defer db.Close()
			rows, err := db.Query(`SELECT id, title, content, owner_id, created_at, updated_at FROM posts`)
			if err != nil {
				c.JSON(500, gin.H{"err": "게시물 조회 실패", "detail": err.Error()})
				return
			}
			posts := []PostView{}
			for rows.Next() {
				var post PostView
				if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.OwnerID, &post.CreatedAt, &post.UpdatedAt); err != nil {
					c.JSON(500, gin.H{"err": "게시물 스캔 실패", "detail": err.Error()})
					return
				}
				posts = append(posts, post)
			}

			c.JSON(http.StatusOK, PostListResponse{
				Posts: posts,
			})
		})

		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			now := time.Now().Format(time.RFC3339)
			db, err := sql.Open("sqlite", "./app.db")

			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, owner_id INTEGER, created_at TEXT, updated_at TEXT)`)
			if err != nil {
				print(err.Error)
				return
			}
			defer tx.Rollback()
			_, err = tx.Exec(`INSERT INTO posts (title, content, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, request.Title, request.Content, user.ID, now, now)
			if err != nil {
				c.JSON(500, gin.H{"err": err.Error()})
				return
			}
			err = tx.Commit()
			if err != nil {
				c.JSON(500, gin.H{"err": "커밋 실패"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "dummy create post handler",
				"todo":    "replace with insert query",
				"post": PostView{
					ID:        1,
					Title:     strings.TrimSpace(request.Title),
					Content:   strings.TrimSpace(request.Content),
					OwnerID:   user.ID,
					CreatedAt: now,
					UpdatedAt: now,
				},
			})
		})

		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			db, err := sql.Open("sqlite", "./app.db")
			if err != nil {
				c.JSON(500, gin.H{"err": "db 연결 실패"})
				return
			}
			defer db.Close()

			row := db.QueryRow(`SELECT id, title, content, owner_id, created_at, updated_at FROM posts WHERE id = ?`, c.Param("id"))

			var post PostView
			if err := row.Scan(&post.ID, &post.Title, &post.Content, &post.OwnerID, &post.CreatedAt, &post.UpdatedAt); err != nil {
				if err == sql.ErrNoRows {
					c.JSON(404, gin.H{"err": "게시물이 없습니다"})
					return
				}
				c.JSON(500, gin.H{"err": "게시물 조회 실패", "detail": err.Error()})
				return
			}

			c.JSON(http.StatusOK, PostResponse{
				Post: PostView{
					ID:        post.ID,
					Title:     post.Title,
					Content:   post.Content,
					OwnerID:   post.OwnerID,
					CreatedAt: post.CreatedAt,
					UpdatedAt: post.UpdatedAt,
				},
			})
		})

		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			now := time.Now().Format(time.RFC3339)

			db, err := sql.Open("sqlite", "./app.db")
			if err != nil {
				c.JSON(500, gin.H{"err": "db 연결 실패"})
				return
			}
			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			fmt.Println(c.Param("id"))
			_, err = tx.Exec(`UPDATE posts SET title =?, content = ?, updated_at = ? WHERE id = ?`, strings.TrimSpace(request.Title), strings.TrimSpace(request.Content), now, c.Param("id"))
			if err != nil {
				c.JSON(500, gin.H{"err": "수정 요청 실패"})
				return
			}
			err = tx.Commit()
			if err != nil {
				c.JSON(500, gin.H{"err": "커밋 실패"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy update post handler",
				"todo":    "replace with ownership check and update query",
				"post": PostView{
					ID:        1,
					Title:     strings.TrimSpace(request.Title),
					Content:   strings.TrimSpace(request.Content),
					OwnerID:   user.ID,
					CreatedAt: "2026-03-19T09:00:00Z",
					UpdatedAt: now,
				},
			})
		})

		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			db, err := sql.Open("sqlite", "./app.db")
			if err != nil {
				c.JSON(500, gin.H{"err": "db 연결 실패"})
				return
			}
			tx, err := db.Begin()
			if err != nil {
				c.JSON(500, gin.H{"err": "tx 시작 실패"})
				return
			}
			fmt.Println(c.Param("id"))
			_, err = tx.Exec(`DELETE FROM posts WHERE id=?`, c.Param("id"))
			if err != nil {
				c.JSON(500, gin.H{"err": "수정 요청 실패"})
				return
			}
			err = tx.Commit()
			if err != nil {
				c.JSON(500, gin.H{"err": "커밋 실패"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy delete post handler",
				"todo":    "replace with ownership check and delete query",
			})
		})
	}

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) close() error {
	return s.db.Close()
}

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	if err := s.execSQLFile(seedFile); err != nil {
		return err
	}
	return nil
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(string(content))
	return err
}

func (s *Store) findUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users
		WHERE username = ?
	`, strings.TrimSpace(username))

	var user User
	var isAdmin int64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	user.IsAdmin = isAdmin == 1

	return user, true, nil
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		tokens: make(map[string]User),
	}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}

	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

func (s *SessionStore) delete(token string) {
	delete(s.tokens, token)
}

// fe 페이지 캐싱으로 테스트에 혼동이 있어, 별도 처리없이 main에 두시면 될 것 같습니다
// registerStaticRoutes 는 정적 파일(HTML, JS, CSS)을 제공하는 라우트를 등록한다.
func registerStaticRoutes(router *gin.Engine) {
	// 브라우저 캐시 비활성화 — 정적 파일과 루트 경로에만 적용
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	headerValue := strings.TrimSpace(c.GetHeader("Authorization"))
	if headerValue != "" {
		return headerValue
	}

	cookieValue, err := c.Cookie(authorizationCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookieValue)
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
