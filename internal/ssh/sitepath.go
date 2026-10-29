package ssh

import "strings"

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
// chrooted reports whether the connection is chrooted (detected per
// connection by the caller). Without a chroot, paths are mapped under
// DocRoot instead.
func SFTPPath(p string, chrooted bool) string {
	p = strings.TrimSpace(p)
	for _, prefix := range []string{"~/htdocs", "htdocs"} {
		if p == prefix {
			p = ""
		} else if strings.HasPrefix(p, prefix+"/") {
			p = strings.TrimPrefix(p, prefix)
		}
	}
	if p == DocRoot || strings.HasPrefix(p, DocRoot+"/") {
		p = strings.TrimPrefix(p, DocRoot)
	}
	rel := normalize("/" + p) // chroot-absolute
	if chrooted {
		return rel
	}
	if rel == "/" {
		return DocRoot
	}
	return DocRoot + rel
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
