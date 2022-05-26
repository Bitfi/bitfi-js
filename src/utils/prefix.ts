function remove(derhex: string) {
  return derhex.slice(0, 2) === '0x'? derhex.slice(2) : derhex
}

export default {
  remove
}