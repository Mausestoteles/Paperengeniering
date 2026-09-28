package io.papermc.paper.dialog;

import io.papermc.paper.adventure.PaperAdventure;
import io.papermc.paper.adventure.providers.ClickCallbackProviderImpl;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import net.minecraft.core.Holder;
import net.minecraft.core.UUIDUtil;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.Tag;
import net.minecraft.network.chat.ClickEvent;
import net.minecraft.resources.Identifier;
import net.minecraft.server.dialog.ActionButton;
import net.minecraft.server.dialog.ButtonListDialog;
import net.minecraft.server.dialog.Dialog;
import net.minecraft.server.dialog.DialogListDialog;
import net.minecraft.server.dialog.SimpleDialog;
import net.minecraft.server.dialog.action.Action;
import net.minecraft.server.dialog.action.CustomAll;
import net.minecraft.server.dialog.action.StaticAction;

/**
 * Hardening: collects the ids of all {@code paper:dialog_click_callback} actions reachable from a dialog.
 * <p>
 * Callback ids are otherwise only protected by being random. Dialogs registered in the (synchronized) dialog
 * registry are sent to <em>every</em> client during configuration though, callback ids included, so without
 * binding the ids to the connections a dialog was actually shown to, any client could trigger any registry
 * dialog callback (e.g. an admin-only dialog) with arbitrary response data.
 */
public final class DialogCallbackCollector {

    private static final Identifier CALLBACK_KEY = PaperAdventure.asVanilla(ClickCallbackProviderImpl.DIALOG_CLICK_CALLBACK_KEY);
    private static final int MAX_DEPTH = 32;

    private DialogCallbackCollector() {
    }

    public static void collect(final Dialog dialog, final Set<UUID> out) {
        collect(dialog, out, Collections.newSetFromMap(new IdentityHashMap<>()), 0);
    }

    private static void collect(final Dialog dialog, final Set<UUID> out, final Set<Dialog> visited, final int depth) {
        if (dialog == null || depth > MAX_DEPTH || !visited.add(dialog)) {
            return;
        }
        dialog.onCancel().ifPresent(action -> collect(action, out));
        if (dialog instanceof final SimpleDialog simple) {
            for (final ActionButton button : simple.mainActions()) {
                collect(button, out);
            }
        }
        if (dialog instanceof final ButtonListDialog list) {
            list.exitAction().ifPresent(button -> collect(button, out));
        }
        if (dialog instanceof final DialogListDialog dialogList) {
            for (final Holder<Dialog> nested : dialogList.dialogs()) {
                collect(nested.value(), out, visited, depth + 1);
            }
        }
    }

    private static void collect(final ActionButton button, final Set<UUID> out) {
        button.action().ifPresent(action -> collect(action, out));
    }

    private static void collect(final Action action, final Set<UUID> out) {
        if (action instanceof final CustomAll custom) {
            if (CALLBACK_KEY.equals(custom.id())) {
                custom.additions().flatMap(DialogCallbackCollector::readId).ifPresent(out::add);
            }
        } else if (action instanceof final StaticAction staticAction
            && staticAction.value() instanceof final ClickEvent.Custom custom
            && CALLBACK_KEY.equals(custom.id())) {
            custom.payload().flatMap(Tag::asCompound).flatMap(DialogCallbackCollector::readId).ifPresent(out::add);
        }
    }

    private static Optional<UUID> readId(final CompoundTag tag) {
        return tag.read(ClickCallbackProviderImpl.ID_KEY, UUIDUtil.CODEC);
    }
}
