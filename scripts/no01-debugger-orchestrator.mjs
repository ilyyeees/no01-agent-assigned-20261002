import crypto from 'node:crypto'
import tls from 'node:tls'

const token = process.env.GH_TOKEN
const repository = process.env.GH_REPOSITORY
if (!token || !repository) throw new Error('missing Actions context')

const api = 'https://api.github.com'
const headers = {
  Accept: 'application/vnd.github+json',
  Authorization: `Bearer ${token}`,
  'X-GitHub-Api-Version': '2026-03-10',
  'Content-Type': 'application/json',
  'User-Agent': 'no01-debugger-boundary-control'
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex')
const nonce = `no01-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`
const headerCanary = `NO01DBG_${crypto.randomBytes(16).toString('hex')}`
const tokenHash = sha256(token)
const canaryHash = sha256(headerCanary)

async function request(path, options = {}) {
  const response = await fetch(`${api}${path}`, {
    ...options,
    headers: {...headers, ...(options.headers || {})}
  })
  const text = await response.text()
  let body
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  return {response, body}
}

async function waitFor(label, fn, attempts = 90, delay = 2000) {
  for (let i = 0; i < attempts; i++) {
    const value = await fn()
    if (value) return value
    if (i % 10 === 0) console.log(`${label}: waiting (${i + 1}/${attempts})`)
    await sleep(delay)
  }
  throw new Error(`${label}: timed out`)
}

function websocketFrame(payload, opcode = 1) {
  const body = Buffer.from(payload)
  const mask = crypto.randomBytes(4)
  let header
  if (body.length < 126) {
    header = Buffer.from([0x80 | opcode, 0x80 | body.length])
  } else if (body.length <= 0xffff) {
    header = Buffer.alloc(4)
    header[0] = 0x80 | opcode
    header[1] = 0x80 | 126
    header.writeUInt16BE(body.length, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = 0x80 | opcode
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(body.length), 2)
  }
  const masked = Buffer.alloc(body.length)
  for (let i = 0; i < body.length; i++) masked[i] = body[i] ^ mask[i % 4]
  return Buffer.concat([header, mask, masked])
}

async function attachAndContinue(rawUrl) {
  const url = new URL(rawUrl)
  if (url.protocol !== 'wss:' || !url.hostname.endsWith('.devtunnels.ms')) {
    throw new Error(`unexpected debugger URL origin: ${url.protocol}//${url.hostname}`)
  }

  return new Promise((resolve, reject) => {
    const socket = tls.connect({host: url.hostname, port: Number(url.port || 443), servername: url.hostname})
    const key = crypto.randomBytes(16).toString('base64')
    let upgraded = false
    let buffer = Buffer.alloc(0)
    let sequence = 1
    let configured = false
    let stoppedCount = 0
    let settled = false
    const timeout = setTimeout(() => finish(new Error('DAP session timed out')), 8 * 60 * 1000)

    const finish = error => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      socket.destroy()
      if (error) reject(error)
      else resolve({stoppedCount})
    }
    const send = (command, args = {}) => {
      const message = {seq: sequence++, type: 'request', command, arguments: args}
      socket.write(websocketFrame(JSON.stringify(message)))
    }
    const handleMessage = payload => {
      let message
      try { message = JSON.parse(payload.toString('utf8')) } catch { return }
      if (message.type === 'response' && message.command === 'initialize' && message.success !== false) {
        send('configurationDone')
        configured = true
      } else if (message.type === 'event' && message.event === 'stopped') {
        stoppedCount++
        send('continue', {threadId: 1, singleThread: false})
      } else if (message.type === 'event' && (message.event === 'terminated' || message.event === 'exited')) {
        finish()
      }
    }
    const parseFrames = () => {
      while (buffer.length >= 2) {
        const first = buffer[0]
        const second = buffer[1]
        let offset = 2
        let length = second & 0x7f
        if (length === 126) {
          if (buffer.length < 4) return
          length = buffer.readUInt16BE(2)
          offset = 4
        } else if (length === 127) {
          if (buffer.length < 10) return
          const longLength = buffer.readBigUInt64BE(2)
          if (longLength > BigInt(Number.MAX_SAFE_INTEGER)) return finish(new Error('oversized WebSocket frame'))
          length = Number(longLength)
          offset = 10
        }
        const masked = Boolean(second & 0x80)
        const maskBytes = masked ? 4 : 0
        if (buffer.length < offset + maskBytes + length) return
        let payload = buffer.subarray(offset + maskBytes, offset + maskBytes + length)
        if (masked) {
          const mask = buffer.subarray(offset, offset + 4)
          payload = Buffer.from(payload)
          for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4]
        }
        buffer = buffer.subarray(offset + maskBytes + length)
        const opcode = first & 0x0f
        if (opcode === 1) handleMessage(payload)
        else if (opcode === 8) finish()
        else if (opcode === 9) socket.write(websocketFrame(payload, 10))
      }
    }

    socket.on('secureConnect', () => {
      const path = `${url.pathname || '/'}${url.search}`
      socket.write([
        `GET ${path} HTTP/1.1`,
        `Host: ${url.host}`,
        'Connection: Upgrade',
        'Upgrade: websocket',
        `Sec-WebSocket-Key: ${key}`,
        'Sec-WebSocket-Version: 13',
        `Authorization: Bearer ${token}`,
        `X-No01-Canary: ${headerCanary}`,
        '', ''
      ].join('\r\n'))
    })
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk])
      if (!upgraded) {
        const end = buffer.indexOf('\r\n\r\n')
        if (end === -1) return
        const responseHead = buffer.subarray(0, end).toString('latin1')
        const status = Number(responseHead.split(' ')[1])
        console.log(`websocket_upgrade_status=${status}`)
        if (status !== 101) return finish(new Error(`WebSocket upgrade failed with ${status}`))
        buffer = buffer.subarray(end + 4)
        upgraded = true
        send('initialize', {
          clientID: 'no01-boundary-control',
          clientName: 'no01 boundary control',
          adapterID: 'github-actions-job',
          pathFormat: 'path',
          linesStartAt1: true,
          columnsStartAt1: true,
          supportsVariableType: true
        })
      }
      if (upgraded) parseFrames()
    })
    socket.on('error', finish)
    socket.on('close', () => {
      if (upgraded && configured) finish()
      else finish(new Error('socket closed before DAP initialization'))
    })
  })
}

console.log(`nonce=${nonce}`)
console.log(`orchestrator_token_sha256=${tokenHash}`)
console.log(`custom_header_sha256=${canaryHash}`)

let result = await request(`/repos/${repository}/actions/workflows/debugger-target.yml/dispatches`, {
  method: 'POST',
  body: JSON.stringify({
    ref: 'main',
    inputs: {nonce, client_token_sha256: tokenHash, header_canary_sha256: canaryHash}
  })
})
console.log(`dispatch_status=${result.response.status}`)
if (result.response.status !== 200 && result.response.status !== 204) {
  throw new Error(`dispatch failed: ${result.response.status}`)
}

const run = await waitFor('target run discovery', async () => {
  const listed = await request(`/repos/${repository}/actions/workflows/debugger-target.yml/runs?event=workflow_dispatch&per_page=20`)
  if (!listed.response.ok) throw new Error(`run list failed: ${listed.response.status}`)
  return listed.body.workflow_runs.find(item => item.display_title === `no01 debugger target ${nonce}`)
})
console.log(`target_run_id=${run.id}`)

const firstJob = await waitFor('initial target completion', async () => {
  const listed = await request(`/repos/${repository}/actions/runs/${run.id}/jobs?filter=latest`)
  if (!listed.response.ok) throw new Error(`job list failed: ${listed.response.status}`)
  const job = listed.body.jobs.find(item => item.name === 'target')
  return job?.status === 'completed' ? job : null
}, 150, 2000)
console.log(`initial_target_job_id=${firstJob.id}`)

result = await request(`/repos/${repository}/actions/jobs/${firstJob.id}/rerun`, {
  method: 'POST',
  body: JSON.stringify({enable_debugger: true})
})
console.log(`debug_rerun_status=${result.response.status}`)
if (result.response.status !== 201) throw new Error(`debug rerun failed: ${result.response.status}`)

const debugJob = await waitFor('debug target job', async () => {
  const listed = await request(`/repos/${repository}/actions/runs/${run.id}/jobs?filter=latest`)
  if (!listed.response.ok) throw new Error(`debug job list failed: ${listed.response.status}`)
  const job = listed.body.jobs.find(item => item.name === 'target' && item.id !== firstJob.id)
  return job?.status === 'in_progress' ? job : null
}, 150, 2000)
console.log(`debug_target_job_id=${debugJob.id}`)

const debuggerUrl = await waitFor('debugger URL', async () => {
  const fetched = await request(`/repos/${repository}/actions/jobs/${debugJob.id}/debugger`)
  if (fetched.response.status === 404 || fetched.response.status === 409 || fetched.response.status === 422) return null
  if (!fetched.response.ok) throw new Error(`debugger URL failed: ${fetched.response.status}`)
  return fetched.body?.debugger_url
}, 90, 2000)
const parsedDebuggerUrl = new URL(debuggerUrl)
console.log(`debugger_origin=${parsedDebuggerUrl.protocol}//${parsedDebuggerUrl.hostname}`)

const dap = await attachAndContinue(debuggerUrl)
console.log(`dap_stopped_events=${dap.stoppedCount}`)

const finishedJob = await waitFor('debug target completion', async () => {
  const listed = await request(`/repos/${repository}/actions/runs/${run.id}/jobs?filter=latest`)
  if (!listed.response.ok) throw new Error(`finished job list failed: ${listed.response.status}`)
  const job = listed.body.jobs.find(item => item.id === debugJob.id)
  return job?.status === 'completed' ? job : null
}, 150, 2000)
console.log(`debug_target_conclusion=${finishedJob.conclusion}`)

const logs = await fetch(`${api}/repos/${repository}/actions/jobs/${debugJob.id}/logs`, {headers, redirect: 'follow'})
console.log(`debug_logs_status=${logs.status}`)
const logText = await logs.text()
for (const line of logText.split(/\r?\n/)) {
  if (/^(target_token_distinct|runner_worker_processes|runner_memory_bytes_scanned|client_token_digest_match|custom_header_digest_match)=/.test(line.trim())) {
    console.log(line.trim())
  }
}
