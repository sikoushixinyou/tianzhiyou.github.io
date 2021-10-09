#include "pin.H"
#include "tag_traits.h"
#include <string.h>

/********************************************************
 uint8_t tags
 ********************************************************/
template <> uint8_t tag_combine(uint8_t const &lhs, uint8_t const &rhs) {
  return lhs | rhs;   //按二进制位进行"或"运算
}

template <> std::string tag_sprint(uint8_t const &tag) {
  std::stringstream ss;
  ss << tag;
  return ss.str();     //返回8位标签转换为string类型后的结果
}

template <> uint8_t tag_alloc<uint8_t>(unsigned int offset) {
  return offset > 0;    //返回传入的偏移是否大于0
}

/********************************************************
tag set tags
********************************************************/

BDDTag bdd_tag;
lb_type tag_traits<lb_type>::cleared_val = 0;

template <> lb_type tag_combine(lb_type const &lhs, lb_type const &rhs) {
  return bdd_tag.combine(lhs, rhs);
}

template <> std::string tag_sprint(lb_type const &tag) {
  return bdd_tag.to_string(tag);
}

template <> lb_type tag_alloc<lb_type>(unsigned int offset) {
  return bdd_tag.insert(offset);
}

std::vector<tag_seg> tag_get(lb_type t) { return bdd_tag.find(t); }
