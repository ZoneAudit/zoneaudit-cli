// Command fakerelease serves a GoReleaser dist/ directory the way GitHub
// serves a release, so CI can run the one-line installers against the
// artefacts built from a pull request before they are published.
//
// It answers only the URLs the installers use:
//
//	HEAD/GET /ZoneAudit/zoneaudit-cli/releases/latest        302 to /releases/tag/<tag>
//	GET      /ZoneAudit/zoneaudit-cli/releases/tag/<tag>     200
//	GET      /ZoneAudit/zoneaudit-cli/releases/download/<tag>/<file>
//	GET      /repos/ZoneAudit/zoneaudit-cli/releases/latest  release JSON (tag_name, assets)
//
// With -tamper, every checksum in checksums.txt is altered, so the
// installers must refuse to install.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const repo = "/ZoneAudit/zoneaudit-cli"

var archiveRe = regexp.MustCompile(`^zoneaudit-cli_(.+)_(linux|darwin|windows)_(amd64|arm64)\.(tar\.gz|zip)$`)

func main() {
	dist := flag.String("dist", "dist", "GoReleaser dist directory")
	addr := flag.String("addr", "127.0.0.1:8765", "listen address")
	tamper := flag.Bool("tamper", false, "serve altered checksums")
	flag.Parse()

	sums, err := os.ReadFile(filepath.Join(*dist, "checksums.txt"))
	if err != nil {
		log.Fatal(err)
	}
	var version string
	var assets []map[string]string
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		if m := archiveRe.FindStringSubmatch(f[1]); m != nil {
			version = m[1]
		}
		assets = append(assets, map[string]string{"name": f[1]})
	}
	if version == "" {
		log.Fatal("no zoneaudit-cli archives listed in checksums.txt")
	}
	assets = append(assets, map[string]string{"name": "checksums.txt"})
	tag := "v" + version

	if *tamper {
		var b strings.Builder
		for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
			b.WriteString(strings.Repeat("0", 64) + line[64:] + "\n")
		}
		sums = []byte(b.String())
	}

	mux := http.NewServeMux()
	mux.HandleFunc(repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+repo+"/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc(repo+"/releases/tag/"+tag, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "release", tag)
	})
	mux.HandleFunc(repo+"/releases/download/"+tag+"/", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if name == "checksums.txt" {
			w.Write(sums)
			return
		}
		if !archiveRe.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(*dist, name))
	})
	mux.HandleFunc("/repos"+repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "assets": assets})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })

	log.Printf("serving %s as release %s on http://%s", *dist, tag, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
