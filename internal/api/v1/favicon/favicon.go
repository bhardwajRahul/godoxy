package favicon

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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
	U "github.com/yusing/go-proxy/internal/api/v1/utils"
	"github.com/yusing/go-proxy/internal/common"
	"github.com/yusing/go-proxy/internal/homepage"
	"github.com/yusing/go-proxy/internal/logging"
	gphttp "github.com/yusing/go-proxy/internal/net/http"
	"github.com/yusing/go-proxy/internal/route/routes"
	route "github.com/yusing/go-proxy/internal/route/types"
	"github.com/yusing/go-proxy/internal/task"
	"github.com/yusing/go-proxy/internal/utils"
)

type content struct {
	header http.Header
	data   []byte
	status int
}

type fetchResult struct {
	icon        []byte
	contentType string
	statusCode  int
	errMsg      string
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

func (res *fetchResult) OK() bool {
	return res.icon != nil
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
	url, alias := req.FormValue("url"), req.FormValue("alias")
	if url == "" && alias == "" {
		U.RespondError(w, U.ErrMissingKey("url or alias"), http.StatusBadRequest)
		return
	}
	if url != "" && alias != "" {
		U.RespondError(w, U.ErrInvalidKey("url and alias are mutually exclusive"), http.StatusBadRequest)
		return
	}

	// try with url
	if url != "" {
		var iconURL homepage.IconURL
		if err := iconURL.Parse(url); err != nil {
			U.RespondError(w, err, http.StatusBadRequest)
			return
		}
		fetchResult := getFavIconFromURL(&iconURL)
		if !fetchResult.OK() {
			http.Error(w, fetchResult.errMsg, fetchResult.statusCode)
			return
		}
		w.Header().Set("Content-Type", fetchResult.contentType)
		U.WriteBody(w, fetchResult.icon)
		return
	}

	// try with route.Homepage.Icon
	r, ok := routes.GetHTTPRoute(alias)
	if !ok {
		U.RespondError(w, errors.New("no such route"), http.StatusNotFound)
		return
	}

	var result *fetchResult
	hp := r.RawEntry().Homepage.GetOverride()
	if !hp.IsEmpty() && hp.Icon != nil {
		if hp.Icon.IconSource == homepage.IconSourceRelative {
			result = findIcon(r, req, hp.Icon.Value)
		} else {
			result = getFavIconFromURL(hp.Icon)
		}
	} else {
		// try extract from "link[rel=icon]"
		result = findIcon(r, req, "/")
	}
	if result.statusCode == 0 {
		result.statusCode = http.StatusOK
	}
	if !result.OK() {
		http.Error(w, result.errMsg, result.statusCode)
		return
	}
	w.Header().Set("Content-Type", result.contentType)
	U.WriteBody(w, result.icon)
}

func getFavIconFromURL(iconURL *homepage.IconURL) *fetchResult {
	switch iconURL.IconSource {
	case homepage.IconSourceAbsolute:
		return fetchIconAbsolute(iconURL.URL())
	case homepage.IconSourceRelative:
		return &fetchResult{statusCode: http.StatusBadRequest, errMsg: "unexpected relative icon"}
	case homepage.IconSourceWalkXCode, homepage.IconSourceSelfhSt:
		return fetchKnownIcon(iconURL)
	}
	return &fetchResult{statusCode: http.StatusBadRequest, errMsg: "invalid icon source"}
}

// cache key can be absolute url or route name.
var (
	iconCache   = make(map[string][]byte)
	iconCacheMu sync.RWMutex
)

func InitIconCache() {
	err := utils.LoadJSONIfExist(common.IconCachePath, &iconCache)
	if err != nil {
		logging.Error().Err(err).Msg("failed to load icon cache")
	} else {
		logging.Info().Msgf("icon cache loaded (%d icons)", len(iconCache))
	}

	task.OnProgramExit("save_favicon_cache", func() {
		iconCacheMu.Lock()
		defer iconCacheMu.Unlock()

		if err := utils.SaveJSON(common.IconCachePath, &iconCache, 0o644); err != nil {
			logging.Error().Err(err).Msg("failed to save icon cache")
		}
	})
}

func routeKey(r route.HTTPRoute) string {
	return r.RawEntry().Provider + ":" + r.TargetName()
}

func ResetIconCache(route route.HTTPRoute) {
	iconCacheMu.Lock()
	defer iconCacheMu.Unlock()
	delete(iconCache, routeKey(route))
}

func loadIconCache(key string) *fetchResult {
	iconCacheMu.RLock()
	defer iconCacheMu.RUnlock()
	icon, ok := iconCache[key]
	if ok && icon != nil {
		logging.Debug().
			Str("key", key).
			Msg("icon found in cache")

		var contentType string
		if bytes.HasPrefix(icon, []byte("<svg")) {
			contentType = "image/svg+xml"
		} else {
			contentType = "image/x-icon"
		}
		return &fetchResult{icon: icon, contentType: contentType}
	}
	return nil
}

func storeIconCache(key string, icon []byte) {
	iconCacheMu.Lock()
	defer iconCacheMu.Unlock()
	iconCache[key] = icon
}

func fetchIconAbsolute(url string) *fetchResult {
	if result := loadIconCache(url); result != nil {
		return result
	}

	resp, err := U.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		if err == nil {
			err = errors.New(resp.Status)
		}
		logging.Error().Err(err).
			Str("url", url).
			Msg("failed to get icon")
		return &fetchResult{statusCode: http.StatusBadGateway, errMsg: "connection error"}
	}

	defer resp.Body.Close()
	icon, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error().Err(err).
			Str("url", url).
			Msg("failed to read icon")
		return &fetchResult{statusCode: http.StatusInternalServerError, errMsg: "internal error"}
	}

	storeIconCache(url, icon)
	return &fetchResult{icon: icon}
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

func fetchKnownIcon(url *homepage.IconURL) *fetchResult {
	// if icon isn't in the list, no need to fetch
	if !url.HasIcon() {
		logging.Debug().
			Str("value", url.String()).
			Str("url", url.URL()).
			Msg("no such icon")
		return &fetchResult{statusCode: http.StatusNotFound, errMsg: "no such icon"}
	}

	return fetchIconAbsolute(url.URL())
}

func fetchIcon(filetype, filename string) *fetchResult {
	result := fetchKnownIcon(homepage.NewSelfhStIconURL(filename, filetype))
	if result.icon == nil {
		return result
	}
	return fetchKnownIcon(homepage.NewWalkXCodeIconURL(filename, filetype))
}

func findIcon(r route.HTTPRoute, req *http.Request, uri string) *fetchResult {
	key := routeKey(r)
	if result := loadIconCache(key); result != nil {
		return result
	}

	result := fetchIcon("png", sanitizeName(r.TargetName()))
	cont := r.RawEntry().Container
	if !result.OK() && cont != nil {
		result = fetchIcon("png", sanitizeName(cont.ImageName))
	}
	if !result.OK() {
		// fallback to parse html
		result = findIconSlow(r, req, uri)
	}
	if result.OK() {
		storeIconCache(key, result.icon)
	}
	return result
}

func findIconSlow(r route.HTTPRoute, req *http.Request, uri string) *fetchResult {
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
		return &fetchResult{statusCode: http.StatusInternalServerError, errMsg: "cannot parse uri"}
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
			return &fetchResult{statusCode: http.StatusBadGateway, errMsg: "connection error"}
		default:
			if loc := c.Header().Get("Location"); loc != "" {
				loc = path.Clean(loc)
				if !strings.HasPrefix(loc, "/") {
					loc = "/" + loc
				}
				if loc == newReq.URL.Path {
					return &fetchResult{statusCode: http.StatusBadGateway, errMsg: "circular redirect"}
				}
				return findIconSlow(r, req, loc)
			}
		}
		return &fetchResult{statusCode: c.status, errMsg: "upstream error: " + string(c.data)}
	}
	// return icon data
	if !gphttp.GetContentType(c.header).IsHTML() {
		return &fetchResult{icon: c.data, contentType: c.header.Get("Content-Type")}
	}
	// try extract from "link[rel=icon]" from path "/"
	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(c.data))
	if err != nil {
		logging.Error().Err(err).
			Str("route", r.TargetName()).
			Msg("failed to parse html")
		return &fetchResult{statusCode: http.StatusInternalServerError, errMsg: "internal error"}
	}
	ele := doc.Find("head > link[rel=icon]").First()
	if ele.Length() == 0 {
		return &fetchResult{statusCode: http.StatusNotFound, errMsg: "icon element not found"}
	}
	href := ele.AttrOr("href", "")
	if href == "" {
		return &fetchResult{statusCode: http.StatusNotFound, errMsg: "icon href not found"}
	}
	// https://en.wikipedia.org/wiki/Data_URI_scheme
	if strings.HasPrefix(href, "data:image/") {
		dataURI, err := dataurl.DecodeString(href)
		if err != nil {
			logging.Error().Err(err).
				Str("route", r.TargetName()).
				Msg("failed to decode favicon")
			return &fetchResult{statusCode: http.StatusInternalServerError, errMsg: "internal error"}
		}
		return &fetchResult{icon: dataURI.Data, contentType: dataURI.ContentType()}
	}
	switch {
	case strings.HasPrefix(href, "http://"), strings.HasPrefix(href, "https://"):
		return fetchIconAbsolute(href)
	default:
		return findIconSlow(r, req, path.Clean(href))
	}
}
