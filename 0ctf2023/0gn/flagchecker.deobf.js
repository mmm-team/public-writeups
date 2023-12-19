MMM = function (g) {
  function j(H, I) {
    var L, M, N, O, P
    N = H & 2147483648
    O = I & 2147483648
    L = H & 1073741824
    M = I & 1073741824
    P = (H & 1073741823) + (I & 1073741823)
    return L & M
      ? P ^ 2147483648 ^ N ^ O
      : L | M
      ? P & 1073741824
        ? P ^ 3221225472 ^ N ^ O
        : P ^ 1073741824 ^ N ^ O
      : P ^ N ^ O
  }
  function o(H, I, J, K, L, M, N) {
    H = j(H, j(j((I & J) | (~I & K), L), N))
    return j((H << M) | (H >>> (32 - M)), I)
  }
  function u(H, I, J, K, L, M, N) {
    H = j(H, j(j((I & K) | (J & ~K), L), N))
    return j((H << M) | (H >>> (32 - M)), I)
  }
  function v(H, I, J, K, L, M, N) {
    H = j(H, j(j(I ^ J ^ K, L), N))
    return j((H << M) | (H >>> (32 - M)), I)
  }
  function w(H, I, J, K, L, M, N) {
    H = j(H, j(j(J ^ (I | ~K), L), N))
    return j((H << M) | (H >>> (32 - M)), I)
  }
  function x(H) {
    var I = '',
      J = '',
      K
    for (K = 0; 3 >= K; K++) {
      J = (H >>> (8 * K)) & 255
      J = '0' + J.toString(16)
      I += J.substr(J.length - 2, 2)
    }
    return I
  }
  var y = [],
    z,
    A,
    B,
    C,
    D,
    E,
    F,
    G
  y = (function (H) {
    var O,
      P = H.length
    O = P + 8
    for (
      var K = 16 * ((O - (O % 64)) / 64 + 1), L = Array(K - 1), M = 0, N = 0;
      N < P;

    ) {
      O = (N - (N % 4)) / 4
      M = (N % 4) * 8
      L[O] |= H[N] << M
      N++
    }
    O = (N - (N % 4)) / 4
    L[O] |= 128 << ((N % 4) * 8)
    L[K - 2] = P << 3
    L[K - 1] = P >>> 29
    return L
  })(g)
  D = 1732584193
  E = 4023233417
  F = 2562383102
  G = 271733878
  for (g = 0; g < y.length; g += 16) {
    z = D
    A = E
    B = F
    C = G
    D = o(D, E, F, G, y[g + 0], 7, 3614090360)
    G = o(G, D, E, F, y[g + 1], 12, 3905402710)
    F = o(F, G, D, E, y[g + 2], 17, 606105819)
    E = o(E, F, G, D, y[g + 3], 22, 3250441966)
    D = o(D, E, F, G, y[g + 4], 7, 4118548399)
    G = o(G, D, E, F, y[g + 5], 12, 1200080426)
    F = o(F, G, D, E, y[g + 6], 17, 2821735955)
    E = o(E, F, G, D, y[g + 7], 22, 4249261313)
    D = o(D, E, F, G, y[g + 8], 7, 1770035416)
    G = o(G, D, E, F, y[g + 9], 12, 2336552879)
    F = o(F, G, D, E, y[g + 10], 17, 4294925233)
    E = o(E, F, G, D, y[g + 11], 22, 2304563134)
    D = o(D, E, F, G, y[g + 12], 7, 1804603682)
    G = o(G, D, E, F, y[g + 13], 12, 4254626195)
    F = o(F, G, D, E, y[g + 14], 17, 2792965006)
    E = o(E, F, G, D, y[g + 15], 22, 1236535329)
    D = u(D, E, F, G, y[g + 1], 5, 4129170786)
    G = u(G, D, E, F, y[g + 6], 9, 3225465664)
    F = u(F, G, D, E, y[g + 11], 14, 643717713)
    E = u(E, F, G, D, y[g + 0], 20, 3921069994)
    D = u(D, E, F, G, y[g + 5], 5, 3593408605)
    G = u(G, D, E, F, y[g + 10], 9, 38016083)
    F = u(F, G, D, E, y[g + 15], 14, 3634488961)
    E = u(E, F, G, D, y[g + 4], 20, 3889429448)
    D = u(D, E, F, G, y[g + 9], 5, 568446438)
    G = u(G, D, E, F, y[g + 14], 9, 3275163606)
    F = u(F, G, D, E, y[g + 3], 14, 4107603335)
    E = u(E, F, G, D, y[g + 8], 20, 1163531501)
    D = u(D, E, F, G, y[g + 13], 5, 2850285829)
    G = u(G, D, E, F, y[g + 2], 9, 4243563512)
    F = u(F, G, D, E, y[g + 7], 14, 1735328473)
    E = u(E, F, G, D, y[g + 12], 20, 2368359562)
    D = v(D, E, F, G, y[g + 5], 4, 4294588738)
    G = v(G, D, E, F, y[g + 8], 11, 2272392833)
    F = v(F, G, D, E, y[g + 11], 16, 1839030562)
    E = v(E, F, G, D, y[g + 14], 23, 4259657740)
    D = v(D, E, F, G, y[g + 1], 4, 2763975236)
    G = v(G, D, E, F, y[g + 4], 11, 1272893353)
    F = v(F, G, D, E, y[g + 7], 16, 4139469664)
    E = v(E, F, G, D, y[g + 10], 23, 3200236656)
    D = v(D, E, F, G, y[g + 13], 4, 681279174)
    G = v(G, D, E, F, y[g + 0], 11, 3936430074)
    F = v(F, G, D, E, y[g + 3], 16, 3572445317)
    E = v(E, F, G, D, y[g + 6], 23, 76029189)
    D = v(D, E, F, G, y[g + 9], 4, 3654602809)
    G = v(G, D, E, F, y[g + 12], 11, 3873151461)
    F = v(F, G, D, E, y[g + 15], 16, 530742520)
    E = v(E, F, G, D, y[g + 2], 23, 3299628645)
    D = w(D, E, F, G, y[g + 0], 6, 4096336452)
    G = w(G, D, E, F, y[g + 7], 10, 1126891415)
    F = w(F, G, D, E, y[g + 14], 15, 2878612391)
    E = w(E, F, G, D, y[g + 5], 21, 4237533241)
    D = w(D, E, F, G, y[g + 12], 6, 1700485571)
    G = w(G, D, E, F, y[g + 3], 10, 2399980690)
    F = w(F, G, D, E, y[g + 10], 15, 4293915773)
    E = w(E, F, G, D, y[g + 1], 21, 2240044497)
    D = w(D, E, F, G, y[g + 8], 6, 1873313359)
    G = w(G, D, E, F, y[g + 15], 10, 4264355552)
    F = w(F, G, D, E, y[g + 6], 15, 2734768916)
    E = w(E, F, G, D, y[g + 13], 21, 1309151649)
    D = w(D, E, F, G, y[g + 4], 6, 4149444226)
    G = w(G, D, E, F, y[g + 11], 10, 3174756917)
    F = w(F, G, D, E, y[g + 2], 15, 718787259)
    E = w(E, F, G, D, y[g + 9], 21, 3951481745)
    D = j(D, z)
    E = j(E, A)
    F = j(F, B)
    G = j(G, C)
  }
  return (x(D) + x(E) + x(F) + x(G)).toLowerCase()
}
class a {
  static ['resultchecker'](c) {
    var e = MMM(c)
    if (e == 'cd9e459ea708a948d5c2f5a6ca8838cf') {
      return 0
    } else {
      return -1
    }
  }
  static ['flagchecker']() {
    if (process.argv.length == 3) {
      var d = process.argv[2]
      console.log('your input is: ', d)
    } else {
      return -1
    }
    if (d.length != 38) {
      return -1
    }
    if (
      d.charAt(0) !== "f" ||
      d.charAt(1) !== "l" ||
      d.charAt(2) !== "a" ||
      d.charAt(3) !== "g" ||
      d.charAt(4) !== "{" ||
      d.charAt(37) !== "}"
    ) {
      return -1
    }
    var e = d.slice(5, 37)
    e = new Buffer.from(e)
    if (a.resultchecker(e) != 0) {
      return -1
    }
    return 0
  }
}
function b() {
  if (a.flagchecker() == 0) {
    console.log('Right!')
  } else {
    console.log('Wrong!')
  }
}
b()
