"""Exercise the pinned ARM64 redirect against its original source fixture."""

# ruff: noqa: E501

import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import build

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/frida-17.16.4/guminterceptor-arm64.c"
MASK64 = (1 << 64) - 1


def test_arm64_build_rejects_an_unverified_version():
    result = subprocess.run(
        [sys.executable, str(ROOT / "build.py"), "--version", "17.9.1", "--skip-build"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "requires Frida 17.16.4" in result.stdout + result.stderr


PRELUDE = r"""
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t guint;
typedef uint32_t guint32;
typedef uint64_t guint64;
typedef unsigned char guint8;
typedef uint64_t GumAddress;
typedef int gboolean;
typedef int arm64_reg;
typedef void *gpointer;
#define TRUE 1
#define FALSE 0
#define ARM64_REG_X16 16
#define ARM64_REG_X17 17
#define ARM64_REG_X0 0
#define ARM64_REG_LR 30
#define GUM_INTERCEPTOR_TYPE_FAST 1
#define GUM_INTERCEPTOR_FULL_REDIRECT_SIZE 16
#define GUM_ADDRESS(p) ((GumAddress) (uintptr_t) (p))
#define GUM_FCDATA(ctx) (&(ctx)->backend_data)
#define g_assert(condition) assert(condition)
#define g_assert_not_reached() abort()
#define g_printerr(...) fprintf(stderr, __VA_ARGS__)
typedef struct {
  guint32 words[8];
  unsigned count;
  GumAddress pc, literal, branch;
  int has_literal;
} GumArm64Writer;
typedef struct { GumArm64Writer writer; } GumInterceptorBackend;
typedef struct { guint redirect_code_size; arm64_reg scratch_reg; } GumArm64FunctionContextData;
typedef struct { gpointer trampoline; } GumCodeDeflector;
typedef struct {
  int type;
  gpointer replacement_function, on_enter_trampoline, function_address;
  gpointer write_redirect, redirect_code;
  GumCodeDeflector *trampoline_deflector;
  GumArm64FunctionContextData backend_data;
} GumFunctionContext;
static void gum_arm64_writer_reset(GumArm64Writer *w, gpointer p) { (void)p; memset(w, 0, sizeof(*w)); }
static void gum_arm64_writer_put_instruction(GumArm64Writer *w, guint32 v) { assert(w->count < 8); w->words[w->count++] = v; }
static void gum_arm64_writer_put_bytes(GumArm64Writer *w, const guint8 *p, guint n) { guint i; assert(n % 4 == 0); for (i = 0; i < n; i += 4) gum_arm64_writer_put_instruction(w, (guint32)p[i] | ((guint32)p[i + 1] << 8) | ((guint32)p[i + 2] << 16) | ((guint32)p[i + 3] << 24)); }
static gboolean gum_arm64_writer_put_ldr_reg_address(GumArm64Writer *w, arm64_reg r, GumAddress v) { gum_arm64_writer_put_instruction(w, 0x58000040u | (guint)r); w->literal = v; w->has_literal = 1; return TRUE; }
static gboolean gum_arm64_writer_put_br_reg(GumArm64Writer *w, arm64_reg r) { gum_arm64_writer_put_instruction(w, 0xd61f0000u | ((guint)r << 5)); return TRUE; }
static gboolean gum_arm64_writer_put_br_reg_no_auth(GumArm64Writer *w, arm64_reg r) { return gum_arm64_writer_put_br_reg(w, r); }
static gboolean gum_arm64_writer_put_b_imm(GumArm64Writer *w, GumAddress v) { w->branch = v; gum_arm64_writer_put_instruction(w, 0x14000000u); return TRUE; }
static gboolean gum_arm64_writer_put_bl_imm(GumArm64Writer *w, GumAddress v) { w->branch = v; gum_arm64_writer_put_instruction(w, 0x94000000u); return TRUE; }
static gboolean gum_arm64_writer_put_adrp_reg_address(GumArm64Writer *w, arm64_reg r, GumAddress v) { w->branch = v; gum_arm64_writer_put_instruction(w, 0x90000000u | (guint)r); return TRUE; }
static void gum_arm64_writer_put_push_reg_reg(GumArm64Writer *w, arm64_reg a, arm64_reg b) { (void)a; (void)b; gum_arm64_writer_put_instruction(w, 0xa9bf7be0u); }
static void gum_arm64_writer_flush(GumArm64Writer *w) { if (w->has_literal) { gum_arm64_writer_put_instruction(w, (guint32)w->literal); gum_arm64_writer_put_instruction(w, (guint32)(w->literal >> 32)); } }
static guint gum_arm64_writer_offset(GumArm64Writer *w) { return w->count * 4; }
"""

MAIN = r"""
int main(int argc, char **argv) {
  GumInterceptorBackend backend = {0};
  GumFunctionContext ctx = {0};
  GumAddress normal, replacement;
  const guint8 custom[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  unsigned i;
  if (argc != 7) return 2;
  ctx.type = atoi(argv[1]);
  ctx.backend_data.scratch_reg = atoi(argv[2]);
  ctx.backend_data.redirect_code_size = (guint)atoi(argv[3]);
  normal = strtoull(argv[4], NULL, 16);
  replacement = strtoull(argv[5], NULL, 16);
  ctx.on_enter_trampoline = (gpointer)(uintptr_t)normal;
  ctx.replacement_function = (gpointer)(uintptr_t)replacement;
  if (atoi(argv[6])) {
    ctx.write_redirect = (gpointer)(uintptr_t)1;
    ctx.redirect_code = (gpointer)custom;
  }
  _gum_interceptor_backend_activate_trampoline(&backend, &ctx, NULL);
  printf("%u", backend.writer.count);
  for (i = 0; i < backend.writer.count; i++) printf(" %08" PRIx32, backend.writer.words[i]);
  printf(" %016" PRIx64 "\n", backend.writer.branch);
  return 0;
}
"""


class RedirectPatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="phantom-arm64-redirect-")
        root = Path(cls.tmp.name)
        relative = Path("subprojects/frida-gum/gum/backend-arm64/guminterceptor-arm64.c")
        target = root / relative
        target.parent.mkdir(parents=True)
        original = SOURCE.read_text()
        target.write_text(original)
        build.apply_arm64_redirect_patch(root)
        build.apply_arm64_redirect_patch(root)  # Applying twice is safe.
        patched = target.read_text()
        start = patched.index("static gboolean\ngum_arm64_writer_put_compact_redirect")
        activation = patched.index("void\n_gum_interceptor_backend_activate_trampoline", start)
        end = patched.index("\nvoid\n_gum_interceptor_backend_deactivate_trampoline", activation)
        cls.original, cls.patched = original, patched
        fixture = root / "fixture.c"
        fixture.write_text(PRELUDE + patched[start:activation] + patched[activation:end] + MAIN)
        cls.binary = root / "fixture"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(fixture), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def emit(self, reg, address, *, fast=False, size=16, custom=False):
        normal = 0x123456789ABC
        replacement = address if fast else 0x765432109ABC
        if not fast:
            normal = address
        proc = subprocess.run([str(self.binary), str(int(fast)), str(reg), str(size), f"{normal:x}", f"{replacement:x}", str(int(custom))], text=True, capture_output=True, check=True)
        fields = proc.stdout.split()
        count = int(fields[0])
        return [int(x, 16) for x in fields[1 : count + 1]], int(fields[count + 1], 16), proc.stderr

    def test_source_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            gum = Path(tmp) / "subprojects/frida-gum/gum/backend-arm64"
            gum.mkdir(parents=True)
            (gum / "guminterceptor-arm64.c").write_text("unexpected source")
            with self.assertRaises(build.BuildError):
                build.apply_arm64_redirect_patch(Path(tmp))

    def test_compact_redirect_preserves_full_address_for_x16_and_x17(self):
        addresses = [0, 1, 0x123456789ABC, (1 << 48) - 1, 0xFFFF123456789ABC, MASK64]
        for reg in (16, 17):
            for address in addresses:
                for fast in (False, True):
                    with self.subTest(reg=reg, address=hex(address), fast=fast):
                        words, _, warning = self.emit(reg, address, fast=fast)
                        self.assertEqual(len(words), 4)
                        self.assertEqual(warning, "")
                        first, second, third, branch = words
                        self.assertEqual(first & 31, reg)
                        high = address >> 48
                        self.assertIn(high, (0, 0xFFFF))
                        self.assertEqual(first & 0xFFE00000, 0xD2800000 if high == 0 else 0x92800000)
                        low = (first >> 5) & 0xFFFF
                        value = low if high == 0 else (~low) & MASK64
                        for word, opcode, shift in ((second, 0xF2A00000, 16), (third, 0xF2C00000, 32)):
                            self.assertEqual(word & 0xFFE00000, opcode)
                            self.assertEqual(word & 31, reg)
                            value = (value & ~(0xFFFF << shift)) | (((word >> 5) & 0xFFFF) << shift)
                        self.assertEqual(value, address)
                        self.assertEqual(branch, 0xD61F0000 | (reg << 5))
                        encoded = b"".join(struct.pack("<I", word) for word in words)
                        self.assertNotIn(encoded[:4], (bytes.fromhex("50 00 00 58"), bytes.fromhex("51 00 00 58")))
                        self.assertNotEqual(encoded[8:12], bytes.fromhex("20 02 1f d6"))

    def test_unsupported_upper_bits_and_register_use_original_ldr_with_warning(self):
        for reg, address in ((16, 0x1234123456789ABC), (17, 0x8000000000000000), (9, 0x123456789ABC)):
            for fast in (False, True):
                with self.subTest(reg=reg, address=hex(address), fast=fast):
                    words, _, warning = self.emit(reg, address, fast=fast)
                    self.assertEqual(words, [0x58000040 | reg, 0xD61F0000 | (reg << 5), address & 0xFFFFFFFF, address >> 32])
                    self.assertIn("ARM64_YONLENDIRME_UYARI", warning)
                    self.assertIn("LDR", warning)
                    self.assertIn("gizlenmedi", warning)

    def test_short_paths_are_unchanged_and_keep_the_selected_target(self):
        for size in (4, 8):
            pattern = rf"      case {size}:\n(.*?)        break;"
            self.assertEqual(re.search(pattern, self.original, re.S).group(0), re.search(pattern, self.patched, re.S).group(0))
            for fast in (False, True):
                words, target, warning = self.emit(16, 0x123456789ABC, fast=fast, size=size)
                self.assertEqual(len(words) * 4, size)
                self.assertEqual(target, 0x123456789ABC)
                self.assertEqual(warning, "")

    def test_custom_redirect_and_deflector_branches_are_unchanged(self):
        marker = "void\n_gum_interceptor_backend_activate_trampoline"
        before = self.original.split(marker, 1)[1]
        after = self.patched.split(marker, 1)[1]
        patterns = (
            r"  if \(ctx->write_redirect != NULL\)\n  \{.*?\n  \}\n  else if \(ctx->trampoline_deflector != NULL\)",
            r"  else if \(ctx->trampoline_deflector != NULL\)\n  \{.*?\n  \}\n  else\n  \{",
        )
        for pattern in patterns:
            self.assertEqual(re.search(pattern, before, re.S).group(0), re.search(pattern, after, re.S).group(0))
        for fast in (False, True):
            words, _, warning = self.emit(9, 0x1234123456789ABC, fast=fast, custom=True)
            self.assertEqual(words, [0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C])
            self.assertEqual(warning, "")


if __name__ == "__main__":
    unittest.main()
