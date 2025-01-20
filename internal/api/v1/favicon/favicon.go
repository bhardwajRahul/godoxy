package favicon

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/vincent-petithory/dataurl"
	"github.com/yusing/go-proxy/internal"
	U "github.com/yusing/go-proxy/internal/api/v1/utils"
	"github.com/yusing/go-proxy/internal/homepage"
	"github.com/yusing/go-proxy/internal/logging"
	gphttp "github.com/yusing/go-proxy/internal/net/http"
	"github.com/yusing/go-proxy/internal/route/routes"
	route "github.com/yusing/go-proxy/internal/route/types"
)

type content struct {
	header http.Header
	data   []byte
	status int
}

func newContent() *content {
	return &content{
		header: make(http.Header),
	}
}

func (c *content) Header() http.Header {
	return c.header
}

func (c *content) Write(data []byte) (int, error) {
	c.data = append(c.data, data...)
	return len(data), nil
}

func (c *content) WriteHeader(statusCode int) {
	c.status = statusCode
}

func (c *content) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("not supported")
}

// GetFavIcon returns the favicon of the route
//
// Returns:
//   - 200 OK: if icon found
//   - 400 Bad Request: if alias is empty or route is not HTTPRoute
//   - 404 Not Found: if route or icon not found
//   - 500 Internal Server Error: if internal error
//   - others: depends on route handler response
func GetFavIcon(w http.ResponseWriter, req *http.Request) {
	alias := req.PathValue("alias")
	if alias == "" {
		U.RespondError(w, U.ErrMissingKey("alias"), http.StatusBadRequest)
		return
	}
	r, ok := routes.GetHTTPRoutes().Load(alias)
	if !ok {
		http.NotFound(w, req)
		return
	}
	switch r := r.(type) {
	case route.HTTPRoute:
		var icon []byte
		var status int
		var errMsg string

		hp := r.RawEntry().Homepage
		if hp != nil && hp.Icon != nil {
			switch hp.Icon.IconSource {
			case homepage.IconSourceAbsolute:
				icon, status, errMsg = fetchIconAbsolute(hp.Icon.Value)
			case homepage.IconSourceRelative:
				icon, status, errMsg = findIcon(r, req, hp.Icon.Value)
			case homepage.IconSourceWalkXCode:
				icon, status, errMsg = fetchWalkxcodeIcon(hp.Icon.Extra.FileType, hp.Icon.Extra.Name)
			case homepage.IconSourceSelfhSt:
				icon, status, errMsg = fetchSelfhStIcon(hp.Icon.Extra.FileType, hp.Icon.Extra.Name)
			}
		} else {
			// try extract from "link[rel=icon]"
			icon, status, errMsg = findIcon(r, req, "/")
		}
		if status != http.StatusOK {
			http.Error(w, errMsg, status)
			return
		}
		U.WriteBody(w, icon)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

// cache key can be absolute url or route name.
var (
	iconCache   = make(map[string][]byte)
	iconCacheMu sync.RWMutex
)

func ResetIconCache(route route.HTTPRoute) {
	iconCacheMu.Lock()
	defer iconCacheMu.Unlock()
	delete(iconCache, route.TargetName())
}

func loadIconCache(key string) (icon []byte, ok bool) {
	iconCacheMu.RLock()
	defer iconCacheMu.RUnlock()
	icon, ok = iconCache[key]
	return
}

func storeIconCache(key string, icon []byte) {
	iconCacheMu.Lock()
	defer iconCacheMu.Unlock()
	iconCache[key] = icon
}

func fetchIconAbsolute(url string) ([]byte, int, string) {
	icon, ok := loadIconCache(url)
	if ok {
		return icon, http.StatusOK, ""
	}

	resp, err := U.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		if err == nil {
			err = errors.New(resp.Status)
		}
		logging.Error().Err(err).
			Str("url", url).
			Msg("failed to get icon")
		return nil, http.StatusBadGateway, "connection error"
	}

	defer resp.Body.Close()
	icon, err = io.ReadAll(resp.Body)
	if err != nil {
		logging.Error().Err(err).
			Str("url", url).
			Msg("failed to read icon")
		return nil, http.StatusInternalServerError, "internal error"
	}

	storeIconCache(url, icon)
	return icon, http.StatusOK, ""
}

var nameSanitizer = strings.NewReplacer(
	"_", "-",
	" ", "-",
	"(", "",
	")", "",
)

func sanitizeName(name string) string {
	return strings.ToLower(nameSanitizer.Replace(name))
}

func fetchWalkxcodeIcon(filetype, name string) ([]byte, int, string) {
	// if icon isn't in the list, no need to fetch
	if !internal.HasWalkxCodeIcon(name, filetype) {
		logging.Debug().
			Str("filetype", filetype).
			Str("name", name).
			Msg("icon not found")
		return nil, http.StatusNotFound, "icon not found"
	}

	icon, ok := loadIconCache("walkxcode/" + filetype + "/" + name)
	if ok {
		return icon, http.StatusOK, ""
	}

	// url := homepage.DashboardIconBaseURL + filetype + "/" + name + "." + filetype
	url := fmt.Sprintf("https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/%s/%s.%s", filetype, name, filetype)
	return fetchIconAbsolute(url)
}

func fetchSelfhStIcon(filetype, reference string) ([]byte, int, string) {
	// if icon isn't in the list, no need to fetch
	if !internal.HasSelfhstIcon(reference, filetype) {
		logging.Debug().
			Str("filetype", filetype).
			Str("reference", reference).
			Msg("icon not found")
		return nil, http.StatusNotFound, "icon not found"
	}

	icon, ok := loadIconCache("selfh.st/" + filetype + "/" + reference)
	if ok {
		return icon, http.StatusOK, ""
	}

	url := fmt.Sprintf("https://cdn.jsdelivr.net/gh/selfhst/icons/%s/%s.%s", filetype, reference, filetype)
	return fetchIconAbsolute(url)
}

func fetchIcon(filetype, filename string) (icon []byte, status int, errMsg string) {
	icon, status, errMsg = fetchSelfhStIcon(filetype, filename)
	if icon != nil {
		return
	}
	icon, status, errMsg = fetchWalkxcodeIcon(filetype, filename)
	return
}

func findIcon(r route.HTTPRoute, req *http.Request, uri string) (icon []byte, status int, errMsg string) {
	key := r.TargetName()
	icon, ok := loadIconCache(key)
	if ok {
		if icon == nil {
			return nil, http.StatusNotFound, "icon not found"
		}
		return icon, http.StatusOK, ""
	}

	icon, status, errMsg = fetchIcon("png", sanitizeName(r.TargetName()))
	cont := r.RawEntry().Container
	if icon == nil && cont != nil {
		icon, status, errMsg = fetchIcon("png", sanitizeName(cont.ImageName))
	}
	if icon == nil {
		// fallback to parse html
		icon, status, errMsg = findIconSlow(r, req, uri)
	}
	// set even if error (nil)
	storeIconCache(key, icon)
	return
}

func findIconSlow(r route.HTTPRoute, req *http.Request, uri string) (icon []byte, status int, errMsg string) {
	ctx, cancel := context.WithTimeoutCause(req.Context(), 3*time.Second, errors.New("favicon request timeout"))
	defer cancel()
	newReq := req.WithContext(ctx)
	newReq.Header.Set("Accept-Encoding", "identity") // disable compression
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		logging.Error().Err(err).
			Str("route", r.TargetName()).
			Str("path", uri).
			Msg("failed to parse uri")
		return nil, http.StatusInternalServerError, "cannot parse uri"
	}
	newReq.URL.Path = u.Path
	newReq.URL.RawPath = u.RawPath
	newReq.URL.RawQuery = u.RawQuery
	newReq.RequestURI = u.String()

	c := newContent()
	r.ServeHTTP(c, newReq)
	if c.status != http.StatusOK {
		switch c.status {
		case 0:
			return nil, http.StatusBadGateway, "connection error"
		default:
			if loc := c.Header().Get("Location"); loc != "" {
				loc = path.Clean(loc)
				if !strings.HasPrefix(loc, "/") {
					loc = "/" + loc
				}
				if loc == newReq.URL.Path {
					return nil, http.StatusBadGateway, "circular redirect"
				}
				return findIconSlow(r, req, loc)
			}
		}
		return nil, c.status, "upstream error: " + http.StatusText(c.status)
	}
	// return icon data
	if !gphttp.GetContentType(c.header).IsHTML() {
		return c.data, http.StatusOK, ""
	}
	// try extract from "link[rel=icon]" from path "/"
	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(c.data))
	if err != nil {
		logging.Error().Err(err).
			Str("route", r.TargetName()).
			Msg("failed to parse html")
		return nil, http.StatusInternalServerError, "internal error"
	}
	ele := doc.Find("head > link[rel=icon]").First()
	if ele.Length() == 0 {
		return nil, http.StatusNotFound, "icon element not found"
	}
	href := ele.AttrOr("href", "")
	if href == "" {
		return nil, http.StatusNotFound, "icon href not found"
	}
	// https://en.wikipedia.org/wiki/Data_URI_scheme
	if strings.HasPrefix(href, "data:image/") {
		dataURI, err := dataurl.DecodeString(href)
		if err != nil {
			logging.Error().Err(err).
				Str("route", r.TargetName()).
				Msg("failed to decode favicon")
			return nil, http.StatusInternalServerError, "internal error"
		}
		return dataURI.Data, http.StatusOK, ""
	}
	switch {
	case strings.HasPrefix(href, "http://"), strings.HasPrefix(href, "https://"):
		return fetchIconAbsolute(href)
	default:
		return findIconSlow(r, req, path.Clean(href))
	}
}
