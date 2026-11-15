package ssh

import (
	"fmt"
	"strings"
)

// DocRoot is a Pressable site's web root as seen from an SSH shell.
// WordPress core lives elsewhere (htdocs/__wp__ symlinks to a shared
// read-only core), but everything a site owns is under here.
const DocRoot = "/srv/htdocs"

// ExecDir resolves a working directory for a shell command: empty means the
// docroot, relative paths are taken from the docroot, absolute paths pass
// through (normalized).
func ExecDir(wd string) string {
	switch {
	case wd == "":
		return DocRoot
	case strings.HasPrefix(wd, "/"):
		return normalize(wd)
	default:
		return normalize(DocRoot + "/" + wd)
	}
}

// systemRoots are top-level directories of the server's filesystem. An
// absolute path starting with one of them means the shell's path, not a
// folder of that name inside the web root.
var systemRoots = map[string]bool{
	"bin": true, "boot": true, "dev": true, "etc": true, "home": true, "lib": true, "lib64": true,
	"media": true, "mnt": true, "opt": true, "proc": true, "root": true, "run": true, "sbin": true,
	"srv": true, "sys": true, "tmp": true, "usr": true, "var": true,
}

// OutsideRootError is a path SFTP can't be sent: one outside the docroot
// on a login confined to it (Confined), or one spelled with ~ or with ..
// segments that climb above the docroot.
type OutsideRootError struct {
	Path     string
	Confined bool
}

func (e *OutsideRootError) Error() string {
	if e.Confined {
		return fmt.Sprintf("Path %s is outside the web root, and this login's SFTP only reaches %s. Use pressable_ssh_exec for other paths (if you meant a folder inside the web root, write it as %s/…)", e.Path, DocRoot, DocRoot)
	}
	return fmt.Sprintf("Path %s points outside the web root. Write it relative to the web root, or as a full path (%s/…, /tmp/…); ~ and .. above the web root aren't followed. pressable_ssh_exec reaches any path", e.Path, DocRoot)
}

// SFTPPath maps a user-supplied path to the path to send over SFTP.
//
// Pressable's SFTP subsystem is chrooted to the docroot, so "/" over SFTP
// is /srv/htdocs in a shell. Agents naturally use shell paths (they see
// them in pressable_ssh_exec output), so both spellings are accepted:
//
//	"wp-content/x"             → docroot-relative
//	"/srv/htdocs/wp-content/x" → same file
//	"~/htdocs/wp-content/x"    → same file
//	"/wp-content/x"            → same file (chroot-absolute)
//
// A shell path outside the docroot is never quietly mapped into it: a dump
// "written to /tmp" must not land in the public web root. A system path
// (/tmp/x, /home/1/x) is sent as written when the connection isn't chrooted
// and is an OutsideRootError when it is; ~/x and ../x are always one.
//
// chrooted reports whether the connection is chrooted (detected per
// connection by the caller; key-based logins seen so far are not). Without
// a chroot, docroot paths are mapped under DocRoot.
func SFTPPath(p string, chrooted bool) (string, error) {
	orig := strings.TrimSpace(p)
	p = orig
	for _, prefix := range []string{"~/htdocs", "htdocs"} {
		if p == prefix {
			p = ""
		} else if strings.HasPrefix(p, prefix+"/") {
			p = strings.TrimPrefix(p, prefix)
		}
	}
	switch {
	case p == DocRoot || strings.HasPrefix(p, DocRoot+"/"):
		p = strings.TrimPrefix(p, DocRoot)
	case strings.HasPrefix(p, "~"):
		return "", &OutsideRootError{Path: orig}
	case strings.HasPrefix(p, "/"):
		if first, _, _ := strings.Cut(strings.TrimPrefix(normalize(p), "/"), "/"); systemRoots[first] {
			if chrooted {
				return "", &OutsideRootError{Path: orig, Confined: true}
			}
			return normalize(p), nil
		}
	}
	if climbsOut(p) {
		return "", &OutsideRootError{Path: orig}
	}
	rel := normalize("/" + p) // chroot-absolute
	if chrooted {
		return rel, nil
	}
	if rel == "/" {
		return DocRoot, nil
	}
	return DocRoot + rel, nil
}

// climbsOut reports whether ".." segments take path above its start.
func climbsOut(path string) bool {
	depth := 0
	for _, part := range strings.Split(path, "/") {
		switch part {
		case "", ".":
		case "..":
			if depth--; depth < 0 {
				return true
			}
		default:
			depth++
		}
	}
	return false
}

// DisplayPath renders an SFTP path as the equivalent shell path, so tool
// output always speaks one dialect.
func DisplayPath(sftpPath string, chrooted bool) string {
	if !chrooted {
		return sftpPath
	}
	if sftpPath == "/" {
		return DocRoot
	}
	return DocRoot + sftpPath
}

// normalize resolves "." and ".." segments. ".." at the root stays at the
// root, so the result can never climb above "/".
func normalize(path string) string {
	parts := strings.Split(path, "/")
	resolved := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		resolved = append(resolved, part)
	}
	return "/" + strings.Join(resolved, "/")
}
