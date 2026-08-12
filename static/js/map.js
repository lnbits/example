
const mapWalletAccount = function (o) {
  return Object.assign({}, o, {
    id: o.id,
    title: o.title,       
    hr_address: o.hr_address,   
    last_height: o.last_height,
    last_scan_height: o.last_scan_height,
    balance: o.balance,
    sp_address: o.sp_address,
    expanded: false  
  })
}

