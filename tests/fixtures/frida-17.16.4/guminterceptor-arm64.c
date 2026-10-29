/*
 * Copyright (C) 2014-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2022-2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 * Frida Gum 7eddbb15847ac18c15d21ae1cff48103acd944d5 (excerpt).
 */

  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64FunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress on_enter;

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
    on_enter = GUM_ADDRESS (ctx->replacement_function);
  else
    on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

#ifdef HAVE_DARWIN
  if (ctx->grafted_hook != NULL)
  {
    _gum_grafted_hook_activate (ctx->grafted_hook);
    return;
  }

  if (ctx->import_target != NULL)
  {
    gum_import_target_activate_all (ctx->import_target);
    return;
  }
#endif

  gum_arm64_writer_reset (aw, prologue);
  aw->pc = GUM_ADDRESS (ctx->function_address);

  if (ctx->write_redirect != NULL)
  {
    gum_arm64_writer_put_bytes (aw, ctx->redirect_code,
        data->redirect_code_size);
  }
  else if (ctx->trampoline_deflector != NULL)
  {
    if (data->redirect_code_size == 8)
    {
      gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X0, ARM64_REG_LR);
      gum_arm64_writer_put_bl_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    else
    {
      g_assert (data->redirect_code_size == 4);
      gum_arm64_writer_put_b_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
  }
  else
  {
    switch (data->redirect_code_size)
    {
      case 4:
        gum_arm64_writer_put_b_imm (aw, on_enter);
        break;
      case 8:
        gum_arm64_writer_put_adrp_reg_address (aw, data->scratch_reg, on_enter);
        gum_arm64_writer_put_br_reg_no_auth (aw, data->scratch_reg);
        break;
      case GUM_INTERCEPTOR_FULL_REDIRECT_SIZE:
        gum_arm64_writer_put_ldr_reg_address (aw, data->scratch_reg, on_enter);
        gum_arm64_writer_put_br_reg (aw, data->scratch_reg);
        break;
      default:
        g_assert_not_reached ();
    }
  }

  gum_arm64_writer_flush (aw);
  g_assert (gum_arm64_writer_offset (aw) <= data->redirect_code_size);
}

void
_gum_interceptor_backend_deactivate_trampoline
