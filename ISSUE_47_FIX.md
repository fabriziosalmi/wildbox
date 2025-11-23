# Issue #47 Fix Summary

## ✅ Fixed in PR #50 (Commit 6a1d1ec)

**Problem**: Docker build failing with 404 errors when downloading lua-resty-http from GitHub.

**Root Cause**: Using unstable `master` branch URLs that can change or become unavailable.

**Solution**: Pinned to stable release `v0.17.2` (latest as of Feb 2024).

### Changed URLs

```diff
- https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http.lua
+ https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http.lua

- https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http_headers.lua
+ https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http_headers.lua

- https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http_connect.lua
+ https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http_connect.lua
```

### Verification

All URLs return HTTP 200:
```bash
$ for file in http.lua http_headers.lua http_connect.lua; do
  curl -s -o /dev/null -w "%{http_code}" \
    "https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/$file"
  echo " - $file"
done
200 - http.lua
200 - http_headers.lua
200 - http_connect.lua
```

### Testing

To verify the fix works:

```bash
# Pull latest changes
git pull origin feature/observability-improvements

# Rebuild gateway service
docker-compose build gateway

# Start services
docker-compose up -d
```

The build should now complete without 404 errors.

---

**Status**: Fixed in commit `6a1d1ec`  
**PR**: #50  
**Reporter**: @mciarciaglini  
**Fix Date**: November 23, 2025
