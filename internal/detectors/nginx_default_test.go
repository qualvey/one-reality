package detectors

import (
	"testing"
)

func TestDetectNginxDefaultPage_StandardNginxWelcome(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`

	headers := map[string]string{
		"Server":       "nginx/1.24.0",
		"Content-Type": "text/html",
	}

	res := DetectNginxDefaultPage(200, headers, []byte(html))
	if !res.IsDefaultPage {
		t.Fatalf("expected IsDefaultPage to be true, got false")
	}
	if res.PageType != "nginx" {
		t.Fatalf("expected PageType to be 'nginx', got %q", res.PageType)
	}
	if res.Title != "Welcome to nginx!" {
		t.Fatalf("expected Title to be 'Welcome to nginx!', got %q", res.Title)
	}
}

func TestDetectNginxDefaultPage_OpenRestyWelcome(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head>
<title>Welcome to OpenResty!</title>
</head>
<body>
<h1>Welcome to OpenResty!</h1>
<p>Thank you for using OpenResty.</p>
</body>
</html>`

	headers := map[string]string{
		"Server": "openresty/1.21.4.1",
	}

	res := DetectNginxDefaultPage(200, headers, []byte(html))
	if !res.IsDefaultPage {
		t.Fatalf("expected OpenResty welcome page to be detected")
	}
	if res.PageType != "openresty" {
		t.Fatalf("expected PageType 'openresty', got %q", res.PageType)
	}
}

func TestDetectNginxDefaultPage_NginxErrorTemplate(t *testing.T) {
	html := `<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>`

	headers := map[string]string{
		"Server": "nginx",
	}

	res := DetectNginxDefaultPage(502, headers, []byte(html))
	if !res.IsDefaultPage {
		t.Fatalf("expected Nginx 502 error template with <center>nginx to be detected")
	}
	if res.PageType != "nginx" {
		t.Fatalf("expected PageType 'nginx', got %q", res.PageType)
	}
}

func TestDetectNginxDefaultPage_DebianNginxTestPage(t *testing.T) {
	html := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<title>Welcome to nginx on Debian!</title>
</head>
<body>
<h1>Welcome to nginx on Debian!</h1>
</body>
</html>`

	headers := map[string]string{
		"Server": "nginx",
	}

	res := DetectNginxDefaultPage(200, headers, []byte(html))
	if !res.IsDefaultPage {
		t.Fatalf("expected Debian Nginx test page to be detected")
	}
}

func TestDetectNginxDefaultPage_LegitimateWebsite(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head>
<title>Apple</title>
<meta name="description" content="Discover the innovative world of Apple." />
</head>
<body>
<h1>iPhone 16 Pro</h1>
<p>Hello Apple Intelligence.</p>
</body>
</html>`

	headers := map[string]string{
		"Server": "AkamaiGHost",
	}

	res := DetectNginxDefaultPage(200, headers, []byte(html))
	if res.IsDefaultPage {
		t.Fatalf("legitimate website should NOT be detected as default page, got: %+v", res)
	}
}
