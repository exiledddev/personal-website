// netlify/edge-functions/block-cloudflare.js
export default async (request, context) => {
  const ip = request.headers.get("cf-connecting-ip")

  if (!ip) {
    return new Response("Forbidden", { status: 403 })
  }

  // Cloudflare IPv4 & IPv6 ranges
  const cloudflareCidrs = [
    // IPv4
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    // IPv6
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32"
  ]

  // helper: check if IP is in CIDR
  if (!cloudflareCidrs.some(cidr => ipInCIDR(ip, cidr))) {
    return new Response("Forbidden", { status: 403 })
  }

  return context.next() // allow request
}

// simple CIDR check for IPv4 & IPv6
function ipInCIDR(ip, cidr) {
  const [range, bits] = cidr.split("/")
  const ipBig = ipToBigInt(ip)
  const rangeBig = ipToBigInt(range)
  const mask = BigInt("0xffffffffffffffffffffffffffffffff") << BigInt((ipBig.toString(2).length - bits))
  return (ipBig & mask) === (rangeBig & mask)
}

function ipToBigInt(ip) {
  if (ip.includes(".")) {
    // IPv4
    return BigInt(
      ip.split(".")
        .map(octet => parseInt(octet))
        .reduce((acc, oct) => (acc << 8n) + BigInt(oct), 0n)
    )
  } else if (ip.includes(":")) {
    // IPv6
    const sections = ip.split(":").map(s => s ? parseInt(s, 16) : 0)
    return sections.reduce((acc, sec) => (acc << 16n) + BigInt(sec), 0n)
  }
  return 0n
}
