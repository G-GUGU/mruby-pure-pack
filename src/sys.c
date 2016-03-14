#include <mruby.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/variable.h>

#include <stdio.h>
#include <stdint.h>

static mrb_value
mrb_sys_endian_little(mrb_state *mrb, mrb_value self)
{
  int x=1;
  if (*(char*)&x) {
    return mrb_true_value(); // little endian
  }else{
    return mrb_false_value(); // big endian
  }
}

static mrb_value
mrb_sys_sizeof_short(mrb_state *mrb, mrb_value self)
{
  int s = sizeof(short);
  return mrb_fixnum_value(s);
}

static mrb_value
mrb_sys_sizeof_int(mrb_state *mrb, mrb_value self)
{
#if defined(MRB_INT16)
  return mrb_fixnum_value(2);
#elif defined(MRB_INT64)
  return mrb_fixnum_value(8);
#else
  return mrb_fixnum_value(4);
#endif
}

static mrb_value
mrb_sys_sizeof_long(mrb_state *mrb, mrb_value self)
{
  int s = sizeof(long);
  return mrb_fixnum_value(s);
}

static mrb_value
mrb_sys_sizeof_long_long(mrb_state *mrb, mrb_value self)
{
  int s = sizeof(long long);
  return mrb_fixnum_value(s);
}

static mrb_value
mrb_sys_sizeof_pointer(mrb_state *mrb, mrb_value self)
{
  int s = sizeof(char*);
  return mrb_fixnum_value(s);
}

/* init */
void
mrb_mruby_pure_pack_gem_init(mrb_state* mrb)
{
  struct RClass *mruby_pure_pack;
  struct RClass *mruby_sys;
  mruby_pure_pack = mrb_define_module(mrb, "PurePack");
  mruby_sys = mrb_define_module_under(mrb, mruby_pure_pack, "SYS");

  mrb_define_class_method(mrb, mruby_sys, "endian_little", mrb_sys_endian_little, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, mruby_sys, "sizeof_short", mrb_sys_sizeof_short, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, mruby_sys, "sizeof_int", mrb_sys_sizeof_int, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, mruby_sys, "sizeof_long", mrb_sys_sizeof_long, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, mruby_sys, "sizeof_long_long", mrb_sys_sizeof_long_long, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, mruby_sys, "sizeof_pointer", mrb_sys_sizeof_pointer, MRB_ARGS_NONE());
}

void
mrb_mruby_pure_pack_gem_final(mrb_state* mrb) {
  // finalizer
}
