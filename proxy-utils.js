/**
 * Validates Supabase Edge Function URLs so the extension token is only sent to *.supabase.co
 * at the exact path /functions/v1/<slug> (optional trailing slash).
 */
const ALLOWED_SLUGS = { 'analyze-email': true, 'report-feedback': true }

function isAllowedSupabaseFunctionUrl(urlString, functionSlug) {
  if (typeof urlString !== 'string' || !urlString.trim()) return false
  if (typeof functionSlug !== 'string' || !functionSlug || !ALLOWED_SLUGS[functionSlug]) return false
  try {
    const u = new URL(urlString.trim())
    if (u.protocol !== 'https:') return false
    if (u.username || u.password) return false
    const host = u.hostname.toLowerCase()
    if (host !== 'supabase.co' && !host.endsWith('.supabase.co')) return false
    const path = u.pathname.replace(/\/+$/, '') || '/'
    const expected = '/functions/v1/' + functionSlug
    if (path !== expected) return false
    return true
  } catch {
    return false
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { isAllowedSupabaseFunctionUrl }
}
