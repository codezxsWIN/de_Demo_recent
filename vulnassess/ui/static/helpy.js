/* Evidence-linked, opt-in report assistance. No HTML from models is executed. */
(() => {
  'use strict';
  const panel = document.querySelector('#helpy-panel');
  if (!panel) return;
  const el = id => document.getElementById('helpy-' + id);
  const messages = [];
  let busy = false, recognition = null, listening = false;
  let requestVersion = 0, pendingRequest = null;
  const status = text => { el('status').textContent = text; };
  function stopAudio() { recognition?.abort(); window.speechSynthesis?.cancel(); }
  function cancelPending() {
    requestVersion++;
    if (pendingRequest) {
      clearTimeout(pendingRequest.timer);
      pendingRequest.controller.abort();
      pendingRequest = null;
    }
    busy = false; el('send').disabled = false;
  }
  function open(value) {
    panel.hidden = !value;
    document.body.classList.toggle('helpy-open', value);
    el('toggle').setAttribute('aria-expanded', String(value));
    if (!value) { cancelPending(); stopAudio(); status('Helpy closed. Any pending reply will not be shown.'); el('toggle').focus(); }
    else el('question').focus();
  }
  el('toggle').onclick = () => open(panel.hidden);
  el('close').onclick = () => open(false);
  panel.addEventListener('keydown', event => { if (event.key === 'Escape') open(false); });
  function message(role, text) {
    const box = document.createElement('article');
    const title = document.createElement('strong'); title.textContent = role;
    const body = document.createElement('p'); body.textContent = text;
    box.append(title, body); el('transcript').append(box);
    messages.push(role + ': ' + text); box.scrollIntoView({block:'nearest'});
    return box;
  }
  function highlight(item) {
    const match = document.querySelector('[data-claim-ref="' + CSS.escape(item.reference) + '"]');
    if (match) {
      let parent = match.parentElement;
      while (parent) { if (parent.tagName === 'DETAILS') parent.open = true; parent = parent.parentElement; }
      match.classList.add('helpy-selected');
    }
    return match;
  }
  function validateAnswer(answer) {
    if (!answer || answer.capture_id !== panel.dataset.capture) throw new Error('Assessment mismatch; answer withheld.');
    if (!['supported','not_established'].includes(answer.status)
        || typeof answer.model !== 'string' || !answer.model.trim()
        || typeof answer.message !== 'string' || !answer.message.trim()
        || !Array.isArray(answer.excerpts) || answer.excerpts.length > 3
        || (answer.status === 'supported' && !answer.excerpts.length)
        || !answer.excerpts.every(item => item && ['reference','text','section'].every(key => typeof item[key] === 'string' && item[key].trim())
          && (item.citations === undefined || (Array.isArray(item.citations) && item.citations.every(value => typeof value === 'string')))
          && (!item.citations?.length || (Number.isInteger(item.batch) && item.batch > 0)))) {
      throw new Error('Helpy returned an invalid response; answer withheld. Your report is unchanged.');
    }
  }
  async function ask(question) {
    if (busy) return;
    question = question.trim();
    const provider = el('provider').value;
    if (!question || question.length > 600) return status('Enter a question of 1–600 characters.');
    if (provider !== 'ollama' && !el('share').checked) return status('Approve sharing with the selected provider, or select Local Ollama.');
    recognition?.abort();
    busy = true; el('send').disabled = true;
    message('You', question); status('Selecting relevant report evidence…');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 55000);
    const version = ++requestVersion;
    pendingRequest = {controller,timer};
    try {
      const response = await fetch('/api/helpy', {
        method:'POST', headers:{'Content-Type':'application/json','X-VulnAssess-Action':'helpy'},
        body:JSON.stringify({capture_id:panel.dataset.capture,question,provider,share_evidence:provider !== 'ollama' && el('share').checked}),
        signal:controller.signal
      });
      const answer = await response.json();
      if (version !== requestVersion) return;
      if (!response.ok) throw new Error(answer.error || 'The provider could not answer.');
      validateAnswer(answer);
      const box = message('Helpy · ' + answer.model, answer.message);
      for (const item of answer.excerpts) {
        const quote = document.createElement('blockquote'); quote.textContent = item.text;
        const link = document.createElement('a'); link.href = '#' + item.section;
        link.textContent = item.reference + (item.citations?.length ? ' · batch ' + item.batch + ' · ' + item.citations.join(', ') : '') + ' · View source';
        link.onclick = event => {
          const target = highlight(item) || document.getElementById(item.section);
          if (target) { event.preventDefault(); target.scrollIntoView({block:'center'}); }
        };
        box.append(quote,link); highlight(item);
        messages.push(item.reference + ': ' + item.text);
      }
      status('Answered from this saved assessment. No new scan.');
      if (el('speak').checked && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
        const speech = new SpeechSynthesisUtterance([answer.message,...answer.excerpts.map(item => item.text)].join(' '));
        speech.onerror = () => status('Spoken reply unavailable. The full text remains in the transcript.');
        window.speechSynthesis.speak(speech);
      }
    } catch (error) {
      if (version !== requestVersion) return;
      const text = error.name === 'AbortError' ? 'Helpy timed out. Your report is unchanged; try again or choose another provider.' : error.message;
      message('Helpy · unavailable', text); status(text);
    } finally {
      clearTimeout(timer);
      if (version === requestVersion) { pendingRequest = null; busy = false; el('send').disabled = false; }
    }
  }
  el('send').onclick = () => ask(el('question').value);
  panel.querySelectorAll('[data-helpy-question]').forEach(button => {
    button.onclick = () => { el('question').value = button.dataset.helpyQuestion; ask(button.dataset.helpyQuestion); };
  });
  el('provider').onchange = () => { cancelPending(); stopAudio(); el('share').checked = false; status('Provider changed. Cloud sharing consent reset; any pending reply will not be shown.'); };
  const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!Recognition) { el('listen').disabled = true; el('listen').textContent = 'Dictation unavailable in this browser'; }
  el('listen').onclick = () => {
    if (listening) return recognition?.stop();
    if (!el('voice-consent').checked) return status('Enable dictation consent first. Your browser may use a remote speech service.');
    window.speechSynthesis?.cancel();
    recognition = new Recognition(); recognition.lang = 'en-IN'; recognition.continuous = false; recognition.interimResults = true;
    const prefix = el('question').value.trim();
    recognition.onstart = () => { listening = true; el('listen').textContent = 'Stop dictation'; status('Listening. Transcription stays editable; press Ask Helpy to send.'); };
    recognition.onresult = event => {
      const words = Array.from(event.results).map(result => result[0].transcript).join(' ');
      el('question').value = [prefix,words].filter(Boolean).join(' ').slice(0,600);
    };
    recognition.onerror = event => status('Dictation unavailable: ' + event.error + '. You can type your question.');
    recognition.onend = () => { listening = false; el('listen').textContent = 'Start dictation'; };
    try { recognition.start(); } catch { status('Microphone could not start. Type your question instead.'); }
  };
  el('voice-consent').onchange = () => { if (!el('voice-consent').checked) recognition?.abort(); };
  el('speak').onchange = () => { if (!el('speak').checked) window.speechSynthesis?.cancel(); };
  el('stop').onclick = () => { stopAudio(); status('Microphone and spoken reply stopped.'); };
  el('clear').onclick = () => { cancelPending(); stopAudio(); messages.length = 0; el('transcript').replaceChildren(); el('question').value = ''; document.querySelectorAll('.helpy-selected').forEach(node => node.classList.remove('helpy-selected')); status('Conversation cleared. Any pending reply will not be shown.'); };
  el('download').onclick = () => {
    const url = URL.createObjectURL(new Blob(['Helpy transcript · ' + panel.dataset.capture + '\n\n' + messages.join('\n\n')],{type:'text/plain'}));
    const link = document.createElement('a'); link.href = url; link.download = 'Helpy-' + panel.dataset.capture + '.txt'; link.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
  };
  window.addEventListener('pagehide',() => { cancelPending(); stopAudio(); });
})();
