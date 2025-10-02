package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTL    time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppId       = errors.New("invalid app id")
	ErrUserExists         = errors.New("user already exists")
)

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:         log,
		usrSaver:    userSaver,
		usrProvider: userProvider,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}

func (auth *Auth) Login(ctx context.Context, email, password string, appId int) (string, error) {
	const op = "auth.Login"

	log := auth.log.With(
		slog.String("op", op),
		slog.String("email", email),
		slog.Int("appId", appId),
	)

	log.Info("logging in user")

	user, err := auth.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			auth.log.Warn("user not found", err)

			return "", fmt.Errorf("%s : %w", op, ErrInvalidCredentials)
		}

		auth.log.Error("failed to get user", err)

		return "", fmt.Errorf("%s : %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		auth.log.Info("invalid password", err)

		return "", fmt.Errorf("%s : %w", op, ErrInvalidCredentials)
	}

	app, err := auth.appProvider.App(ctx, appId)
	if err != nil {
		if errors.Is(err, ErrInvalidAppId) {
			auth.log.Warn("invalid app id", err)

			return "", fmt.Errorf("%s : %w", op, ErrInvalidAppId)
		}

		return "", fmt.Errorf("%s : %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, auth.tokenTTL)
	if err != nil {
		auth.log.Error("failed to create token", err)

		return "", fmt.Errorf("%s : %w", op, err)
	}

	return token, nil
}

func (auth *Auth) RegisterNewUser(ctx context.Context, email, pass string) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := auth.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Failed to hash password", err)

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := auth.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", err)

			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}

		log.Error("Failed to save user", err)

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("Successfully saved user")

	return id, nil
}

func (auth *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	op := "auth.IsAdmin"
	log := auth.log.With(
		slog.String("op", op),
		slog.Int64("userID", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := auth.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		auth.log.Error("failed to check if user is admin", err)

		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("isAdmin", isAdmin))

	return isAdmin, nil
}
