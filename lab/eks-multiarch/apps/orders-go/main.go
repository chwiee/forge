// orders-go: the "clean" app of the lab. Up-to-date Go toolchain and libraries,
// distroless runtime: forge must approve it and publish the multi-arch index.
package main

import (
	"net/http"
	"os"
	"runtime"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type order struct {
	ID    string  `json:"id"`
	Item  string  `json:"item" binding:"required"`
	Total float64 `json:"total" binding:"gte=0"`
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	var (
		mu     sync.Mutex
		orders = map[string]order{}
	)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	// /info proves which image variant the node pulled: same tag, different arch.
	r.GET("/info", func(c *gin.Context) {
		host, _ := os.Hostname()
		c.JSON(http.StatusOK, gin.H{
			"app": "orders-go", "arch": runtime.GOARCH, "os": runtime.GOOS,
			"go": runtime.Version(), "pod": host,
		})
	})

	r.POST("/orders", func(c *gin.Context) {
		var o order
		if err := c.ShouldBindJSON(&o); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		o.ID = uuid.NewString()
		mu.Lock()
		orders[o.ID] = o
		mu.Unlock()
		c.JSON(http.StatusCreated, o)
	})

	r.GET("/orders/:id", func(c *gin.Context) {
		mu.Lock()
		o, ok := orders[c.Param("id")]
		mu.Unlock()
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
			return
		}
		c.JSON(http.StatusOK, o)
	})

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	if err := r.Run(addr); err != nil {
		panic(err)
	}
}
