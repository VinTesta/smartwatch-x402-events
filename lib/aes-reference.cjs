// Fase 1 (AES) — lógica de decifragem/análise do lado do servidor (só o módulo crypto do Node).
// Cópia de prot-simple_sig/tools/aes-reference.cjs (sem a CLI). Mantenha as duas em sincronia.
//
// Protocolo A128CBC-HS256-RP: AES-128-CBC + HMAC-SHA256 (encrypt-then-MAC) com bloco
// aleatório prefixado. Ver prot-simple_sig/shared/aes-protocol.js.
'use strict'

const crypto = require('crypto')

const ALG = 'A128CBC-HS256-RP'

// Precisa bater com shared/config.js (KAT.aes).
const KAT_AES = {
  key: '000102030405060708090a0b0c0d0e0f',
  pt: '00112233445566778899aabbccddeeff',
}

// ------------------------------------------------------------------ helpers
const hex = (h) => Buffer.from(h, 'hex')
const xor = (a, b) => Buffer.from(a.map((v, i) => v ^ b[i]))
const blocks = (buf) => {
  const out = []
  for (let i = 0; i < buf.length; i += 16) out.push(buf.subarray(i, i + 16))
  return out
}

function ecbEncrypt(key, block) {
  const c = crypto.createCipheriv('aes-128-ecb', key, null)
  c.setAutoPadding(false)
  return Buffer.concat([c.update(block), c.final()])
}

function ecbDecrypt(key, block) {
  const d = crypto.createDecipheriv('aes-128-ecb', key, null)
  d.setAutoPadding(false)
  return Buffer.concat([d.update(block), d.final()])
}

// IV que, em CBC, transforma `pt` no bloco `c`: IV = D_K(c) xor pt
const ivFor = (key, c, pt) => xor(ecbDecrypt(key, c), pt)

// ------------------------------------------------------------------ envelope
/**
 * Abre um envelope A128CBC-HS256-RP produzido pelo relógio.
 * @param env  { v, alg, kid, n, ct (b64), mac (b64), rng }
 * @param keys { enc: hex(16B), mac: hex(32B) }
 * @param opts { ivPrefixed?: boolean }  // só se o KAT mostrar que o nativo embute o IV na saída
 */
function openEnvelope(env, keys, opts = {}) {
  if (!env || env.v !== 1 || env.alg !== ALG) throw new Error('versão/algoritmo não suportado')
  const encKey = hex(keys.enc)
  const macKey = hex(keys.mac)
  if (encKey.length !== 16 || macKey.length !== 32) throw new Error('chaves com tamanho errado')

  const ct = Buffer.from(String(env.ct), 'base64')
  const mac = Buffer.from(String(env.mac), 'base64')
  const n = env.n
  const extra = opts.ivPrefixed ? 16 : 0
  if (!Number.isInteger(n) || n < 32 || n % 16 !== 0) throw new Error('n inválido')
  if (ct.length % 16 !== 0 || ct.length < n + extra) throw new Error('ciphertext com tamanho inválido')

  // 1) MAC primeiro (encrypt-then-MAC): nada é decifrado se o MAC não bater.
  const header = Buffer.from(env.v + '.' + env.alg + '.' + env.kid + '.' + n + '.', 'ascii')
  const expected = crypto.createHmac('sha256', macKey).update(header).update(ct).digest()
  if (mac.length !== expected.length || !crypto.timingSafeEqual(mac, expected)) {
    throw new Error('MAC inválido')
  }

  // 2) CBC: o bloco 0 (prefixo aleatório cifrado) serve de IV para os blocos 1..n/16-1.
  //    O IV nativo nunca é necessário e o prefixo é descartado.
  const body = ct.subarray(extra)
  const d = crypto.createDecipheriv('aes-128-cbc', encKey, body.subarray(0, 16))
  d.setAutoPadding(false)
  const padded = Buffer.concat([d.update(body.subarray(16, n)), d.final()])

  // 3) PKCS#7 manual
  const p = padded[padded.length - 1]
  if (p < 1 || p > 16 || p > padded.length) throw new Error('padding inválido')
  for (let i = padded.length - p; i < padded.length; i++) {
    if (padded[i] !== p) throw new Error('padding inválido')
  }
  return { plaintext: padded.subarray(0, padded.length - p).toString('utf8'), bytes: padded.length - p }
}

// ------------------------------------------------------------------ KAT
/** Analisa o relatório do botão "2 · AES KAT" e descobre o comportamento do AES nativo. */
function analyzeKat(kat) {
  const K = hex(KAT_AES.key)
  const P = hex(KAT_AES.pt)
  const a = (kat && kat.aes) || {}
  const out = {
    sha256: kat && kat.sha256 ? !!kat.sha256.ok : null,
    hmac: kat && kat.hmac ? !!kat.hmac.ok : null,
  }
  if (!a.t1 || !a.t1.hex) return Object.assign(out, { error: 't1 ausente: ' + JSON.stringify(a.t1) })

  const c1 = blocks(hex(a.t1.hex))
  let layout = 'desconhecido'
  let iv = null
  if (c1.length === 1) {
    layout = 'cbc-sem-padding'
    iv = ivFor(K, c1[0], P)
  } else if (c1.length === 2) {
    // A) CBC com PKCS#7 nativo: bloco extra = E(K, 0x10..10 xor C0)
    const padBlock = Buffer.alloc(16, 16)
    if (ecbEncrypt(K, xor(padBlock, c1[0])).equals(c1[1])) {
      layout = 'cbc+pkcs7-nativo'
      iv = ivFor(K, c1[0], P)
    } else if (ivFor(K, c1[1], P).equals(c1[0])) {
      // B) IV embutido no começo da saída
      layout = 'iv-prefixado'
      iv = c1[0]
    }
  }
  out.layout = layout
  out.iv = iv ? iv.toString('hex') : null
  out.ivZero = iv ? iv.every((b) => b === 0) : null

  const off = layout === 'iv-prefixado' ? 1 : 0
  const ivOf = (h) => {
    const b = blocks(hex(h))
    return layout === 'iv-prefixado' ? b[0] : ivFor(K, b[0], P)
  }

  // t4: encadeamento CBC padrão => C1 = E(K, P xor C0)
  if (a.t4 && a.t4.hex) {
    const b = blocks(hex(a.t4.hex))
    out.t4_cbcEncadeado = b.length >= 2 + off ? ecbEncrypt(K, xor(P, b[off])).equals(b[off + 1]) : false
  }

  // t2 (mesma instância) e t3 (instância nova): o IV muda?
  const classify = (t) => {
    if (!t || !t.hex || !iv) return t && t.error ? 'erro: ' + t.error : null
    const ivT = ivOf(t.hex)
    if (ivT.equals(iv)) return 'iv-fixo'
    // estilo mbedTLS: o buffer de IV é sobrescrito com o último bloco cifrado da chamada anterior
    if (ivT.equals(c1[c1.length - 1])) return 'iv-encadeado (estado mantido entre chamadas)'
    return 'iv-diferente: ' + ivT.toString('hex')
  }
  out.t2_mesmaInstancia = classify(a.t2)
  out.t3_novaInstancia = classify(a.t3)

  // t6: key_encrypt=1 com a mesma chave crua
  if (a.t6) {
    out.t6_keyEncrypt1 = a.t6.error
      ? 'erro: ' + a.t6.error
      : a.t6.equalsT1
        ? 'mesmo resultado: key_encrypt não altera a chave efetiva'
        : 'resultado diferente: com key_encrypt=1 a chave efetiva muda (servidor NÃO decifra)'
  }
  out.t7_15bytes = a.t7 ? (a.t7.error ? 'erro: ' + a.t7.error : a.t7.len + ' bytes') : null
  out.t5_roundtrip = a.t5 ? (a.t5.error ? 'erro: ' + a.t5.error : a.t5.ok) : null
  out.perf = a.perf || null

  out.protocoloCompativel =
    layout === 'cbc-sem-padding' || layout === 'cbc+pkcs7-nativo'
      ? 'sim (opts.ivPrefixed = false)'
      : layout === 'iv-prefixado'
        ? 'sim, com opts.ivPrefixed = true'
        : 'NÃO: layout desconhecido, investigar'
  return out
}

// ------------------------------------------------------------------ RNG
/** Estatística simples das chaves cruas do createChiper(). Amostra pequena: só pega falhas grosseiras. */
function analyzeRng(r) {
  const raw = Buffer.from((r && r.raw) || '', 'base64')
  if (!raw.length) return { error: 'sem amostras', relatorio: r }
  const keyLen = r.keyLen || 16
  const keys = new Set()
  for (let i = 0; i < raw.length; i += keyLen) keys.add(raw.subarray(i, i + keyLen).toString('hex'))
  const count = Math.floor(raw.length / keyLen)

  const hist = new Array(256).fill(0)
  let ones = 0
  for (const b of raw) {
    hist[b]++
    for (let x = b; x; x >>= 1) ones += x & 1
  }
  const exp = raw.length / 256
  const chi2 = hist.reduce((s, o) => s + ((o - exp) * (o - exp)) / exp, 0)
  const z = (chi2 - 255) / Math.sqrt(2 * 255) // aprox. normal, gl = 255
  const onesRatio = ones / (raw.length * 8)

  const duplicates = count - keys.size
  let veredito = 'sem anomalias óbvias (amostra pequena; não prova qualidade criptográfica)'
  if (duplicates > 0) veredito = 'REPROVADO: chaves repetidas'
  else if (Math.abs(z) > 4 || Math.abs(onesRatio - 0.5) > 0.03) veredito = 'SUSPEITO: distribuição fora do esperado'

  return {
    bytes: raw.length,
    chaves: count,
    duplicadas: duplicates,
    chi2: Number(chi2.toFixed(1)),
    z: Number(z.toFixed(2)),
    proporcaoDeUns: Number(onesRatio.toFixed(4)),
    msNoRelogio: r.ms,
    veredito,
  }
}

// ------------------------------------------------------------------ diagnóstico
/** Resume o botão "0 · Diagnóstico": o que bateu com os vetores e o IV de cada amostra AES. */
function analyzeDiag(d) {
  const entries = Object.keys(d || {}).filter((k) => typeof d[k] === 'string')
  const matched = entries.filter((k) => /match=true/.test(d[k]))
  const mismatched = entries.filter((k) => /match=false/.test(d[k]))
  const threw = entries.filter((k) => /^THROW/.test(d[k]))

  const aes = ((d && d.aesSamples) || []).map((s) => {
    try {
      const K = hex(s.key)
      const P = hex(s.pt)
      const c = blocks(hex(s.ct))
      const iv = ivFor(K, c[0], P)
      return {
        name: s.name,
        bytes: c.length * 16,
        iv: iv.toString('hex'),
        ivZero: iv.every((b) => b === 0),
        bloco0IgualEcb: c[0].equals(ecbEncrypt(K, P)),
      }
    } catch (e) {
      return { name: s.name, error: e.message }
    }
  })

  return { bateram: matched, naoBateram: mismatched, lancaramErro: threw, aes, ms: d && d.ms }
}

// ------------------------------------------------------------------ dispatcher
/**
 * Trata o corpo enviado pelo app-side: { kind, payload, side }.
 * Devolve um objeto pequeno (vai aparecer na tela do relógio).
 */
function handle(body, keys, opts = {}) {
  const kind = body && body.kind
  const payload = body && body.payload
  // O relógio falhou antes de montar o relatório/envelope: repassa o erro de lá.
  if (payload && payload.fatal) return { ok: false, kind, error: 'erro no relógio: ' + payload.fatal }
  try {
    switch (kind) {
      case 'probe':
        return {
          ok: true,
          kind,
          bigint: payload && payload.js && payload.js.BigInt,
          api: payload && payload.system && payload.system.minAPI,
          crypto: payload && payload.crypto && payload.crypto.exports,
          rng: payload && payload.rngSource,
        }
      case 'diag':
        return { ok: true, kind, analise: analyzeDiag(payload) }
      case 'aes.kat':
        return { ok: true, kind, analise: analyzeKat(payload), aprendido: payload && payload.learned }
      case 'aes.rng':
        return { ok: true, kind, analise: analyzeRng(payload) }
      case 'aes.msg': {
        const r = openEnvelope(payload, keys, opts)
        return { ok: true, kind, plaintext: r.plaintext, bytes: r.bytes, rng: payload.rng, msNoRelogio: payload.t_ms }
      }
      default:
        return { ok: false, error: 'kind desconhecido: ' + kind }
    }
  } catch (e) {
    return { ok: false, kind, error: e.message }
  }
}

module.exports = { ALG, openEnvelope, analyzeKat, analyzeRng, analyzeDiag, handle }
