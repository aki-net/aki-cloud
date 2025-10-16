# Redirect Options Explained

## What are "Preserve Path" and "Preserve Query"?

When you set up a redirect from one domain to another, you have control over what happens to different parts of the URL. Here's a simple explanation:

### URL Structure
A typical URL has these parts:
```
https://example.com/blog/article?utm_source=google&id=123#section
        ↑           ↑              ↑                      ↑
     Domain       Path         Query Parameters      Fragment
```

## 🗂️ Preserve Path Option

**What it does:** Controls whether the path (everything after the domain) is kept or removed during redirect.

### When ENABLED (✓):
```
User visits:  oldsite.com/blog/my-article
Redirects to: newsite.com/blog/my-article
              ↑ The path "/blog/my-article" is preserved
```

**Use this when:**
- Your new site has the same structure as the old one
- You want to redirect users to the exact same page on the new domain
- You're moving to a new domain but keeping all your URLs the same

### When DISABLED (✗):
```
User visits:  oldsite.com/blog/my-article
Redirects to: newsite.com
              ↑ User lands on homepage, path is removed
```

**Use this when:**
- Your new site has a different structure
- You want all traffic to go to your homepage
- The old paths don't exist on the new site

---

## 🔍 Preserve Query Parameters Option

**What it does:** Controls whether URL parameters (the stuff after `?`) are kept or removed.

### When ENABLED (✓):
```
User visits:  oldsite.com/shop?product_id=123&utm_source=email&campaign=summer
Redirects to: newsite.com/shop?product_id=123&utm_source=email&campaign=summer
              ↑ All parameters are preserved
```

**Use this when:**
- You need to track marketing campaigns (utm_source, utm_campaign, etc.)
- Your new site uses the same parameter structure
- You want to maintain analytics tracking
- The target site needs these parameters to function properly

### When DISABLED (✗):
```
User visits:  oldsite.com/shop?product_id=123&utm_source=email&campaign=summer
Redirects to: newsite.com/shop
              ↑ Clean URL, all parameters removed
```

**Use this when:**
- You want clean URLs on the target site
- The parameters from the old site aren't compatible
- You don't need tracking information
- The target site doesn't use these parameters

---

## 📊 Common Scenarios

### Scenario 1: Complete Site Migration (Same Structure)
- **Preserve Path:** ✓ ENABLED
- **Preserve Query:** ✓ ENABLED
- **Why:** You want everything to work exactly as before, just on a new domain

### Scenario 2: Redirecting to a Landing Page
- **Preserve Path:** ✗ DISABLED
- **Preserve Query:** ✓ ENABLED  
- **Why:** You want everyone on a specific page but keep tracking codes

### Scenario 3: Clean Redirect to New Site
- **Preserve Path:** ✗ DISABLED
- **Preserve Query:** ✗ DISABLED
- **Why:** Fresh start, everyone goes to homepage with no baggage

### Scenario 4: Blog Migration
- **Preserve Path:** ✓ ENABLED
- **Preserve Query:** ✗ DISABLED
- **Why:** Keep article URLs working but remove old tracking parameters

---

## 🎯 Real-World Examples

### E-commerce Site Migration
```
Old: shop-old.com/products/shoes/nike-air?size=10&color=black&ref=google
New: shop-new.com/products/shoes/nike-air?size=10&color=black&ref=google
```
Both options ENABLED - customers land on the exact product with their selections intact.

### Marketing Campaign Redirect
```
Old: promo2023.com/special-offer?utm_source=facebook&utm_campaign=blackfriday
New: mainsite.com?utm_source=facebook&utm_campaign=blackfriday
```
Path DISABLED (everyone goes to homepage), Query ENABLED (track the campaign source).

### Simple Domain Change
```
Old: company-old.com/about/team?lang=en
New: company-new.com
```
Both DISABLED - just send everyone to the new homepage.

---

## 💡 Pro Tips

1. **Test your redirects** with different URL patterns before going live
2. **Consider SEO impact** - preserving paths helps maintain search rankings
3. **Think about user experience** - will users find what they expect?
4. **Check analytics** - make sure tracking still works if you need it
5. **Document your choices** - future you will thank present you

## ❓ Still Confused?

Think of it this way:
- **Preserve Path** = Keep the room number when moving to a new building
- **Preserve Query** = Keep the visitor's badge and tracking info when they enter
