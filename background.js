// Firefox - background.js v2.0
// Uses Supabase proxy instead of direct Anthropic API call

browser.runtime.onInstalled.addListener(() => {
  console.log('Outlook Email Evaluator installed.')
})

browser.runtime.onMessage.addListener((message, sender) => {
  if (message.type === 'PING') {
    return Promise.resolve(true)
  }

  if (message.type === 'ANALYZE_EMAIL') {
    const tabId = sender.tab?.id
    if (!tabId) return false

    return browser.storage.local.get(['proxyUrl', 'extensionToken', 'customPrompt', 'tenantDomain']).then(async (result) => {
      const proxyUrl    = (result.proxyUrl || '').trim()
      const extToken    = (result.extensionToken || '').trim()
      const customPrompt = result.customPrompt || ''
      const tenantDomain = (result.tenantDomain || '').trim()

      if (!proxyUrl) {
        browser.tabs.sendMessage(tabId, { type: 'ANALYSIS_DONE', error: 'No proxy URL set. Click the extension icon and add your Supabase proxy URL.' })
        return
      }
      if (!isAllowedSupabaseFunctionUrl(proxyUrl, 'analyze-email')) {
        browser.tabs.sendMessage(tabId, { type: 'ANALYSIS_DONE', error: 'Invalid proxy URL. Use your Supabase HTTPS URL ending in /functions/v1/analyze-email' })
        return
      }
      if (!extToken) {
        browser.tabs.sendMessage(tabId, { type: 'ANALYSIS_DONE', error: 'No extension token set. Click the extension icon and add your token.' })
        return
      }

      try {
        const response = await fetch(proxyUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-extension-token': extToken,
          },
          body: JSON.stringify({ emailData: message.emailData, customPrompt, tenantDomain })
        })

        if (response.status === 429) {
          browser.tabs.sendMessage(tabId, { type: 'ANALYSIS_DONE', error: 'Please wait 5 seconds before analyzing another email.' })
          return
        }
        if (!response.ok) {
          const err = await response.json().catch(() => ({}))
          browser.tabs.sendMessage(tabId, { type: 'ANALYSIS_DONE', error: `Proxy error ${response.status}: ${err.error || response.statusText}` })
          return
        }

        const data = await response.json()
        browser.tabs.sendMessage(tabId, { type: 'ANALYSIS_DONE', result: data.result })

      } catch (err) {
        browser.tabs.sendMessage(tabId, { type: 'ANALYSIS_DONE', error: 'Request failed: ' + err.message })
      }
    })
  }

  if (message.type === 'SUBMIT_FEEDBACK') {
    const tabId = sender.tab?.id
    if (!tabId) return false

    return browser.storage.local.get(['proxyUrl', 'extensionToken']).then(async (result) => {
      const proxyUrl = (result.proxyUrl || '').trim()
      const extToken = (result.extensionToken || '').trim()

      if (!proxyUrl || !extToken) {
        browser.tabs.sendMessage(tabId, { type: 'FEEDBACK_RESULT', success: false, error: 'Extension not configured.' })
        return
      }

      const feedbackUrl = proxyUrl.replace(/\/analyze-email\/?$/, '/report-feedback')
      if (!isAllowedSupabaseFunctionUrl(feedbackUrl, 'report-feedback')) {
        browser.tabs.sendMessage(tabId, { type: 'FEEDBACK_RESULT', success: false, error: 'Could not derive feedback URL.' })
        return
      }

      try {
        const response = await fetch(feedbackUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-extension-token': extToken,
          },
          body: JSON.stringify(message.payload)
        })

        if (response.ok) {
          browser.tabs.sendMessage(tabId, { type: 'FEEDBACK_RESULT', success: true })
        } else {
          const err = await response.json().catch(() => ({}))
          browser.tabs.sendMessage(tabId, { type: 'FEEDBACK_RESULT', success: false, error: err.error || `Error ${response.status}` })
        }
      } catch (err) {
        browser.tabs.sendMessage(tabId, { type: 'FEEDBACK_RESULT', success: false, error: err.message })
      }
    })
  }

  return false
})
