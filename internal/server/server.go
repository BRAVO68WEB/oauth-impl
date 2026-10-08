package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/oauth-impl/internal/app"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/queue"
)

type Server struct {
	cfg    *config.Config
	router *chi.Mux
	server *http.Server
	close  func()
}

func New(cfg *config.Config, db *database.DB, q queue.Queue) (*Server, error) {
	built, err := app.Build(cfg, db, q)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, router: built.Mux, close: built.Close}
	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return s, nil
}

func (s *Server) GetRouter() *chi.Mux {
	return s.router
}

func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.close != nil {
		s.close()
	}
	return s.server.Close()
}

func (s *Server) StartWithGracefulShutdown() {
	go func() {
		log.Printf("Starting OAuth server on %s://%s:%d", "http", s.cfg.Server.Host, s.cfg.Server.Port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	if s.close != nil {
		s.close()
	}

	log.Println("Server exited")
}
