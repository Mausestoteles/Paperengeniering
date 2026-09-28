package io.papermc.paper.connection;

import com.google.common.base.Preconditions;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.cookie.ClientboundCookieRequestPacket;
import net.minecraft.network.protocol.cookie.ServerboundCookieResponsePacket;
import net.minecraft.resources.Identifier;
import org.bukkit.NamespacedKey;
import org.bukkit.craftbukkit.util.CraftNamespacedKey;
import org.jspecify.annotations.NullMarked;

@NullMarked
public abstract class ReadablePlayerCookieConnectionImpl implements ReadablePlayerCookieConnection {

    // Because we support async cookies, order is not promised.
    private final Map<Identifier, CookieFuture> requestedCookies = new ConcurrentHashMap<>();
    private final Connection connection;

    public ReadablePlayerCookieConnectionImpl(final Connection connection) {
        this.connection = connection;
    }

    @Override
    public CompletableFuture<byte[]> retrieveCookie(final NamespacedKey key) {
        Preconditions.checkArgument(key != null, "Cookie key cannot be null");

        CompletableFuture<byte[]> future = new CompletableFuture<>();
        Identifier id = CraftNamespacedKey.toMinecraft(key);
        // Hardening start - share an outstanding request for the same key instead of orphaning its future
        final CookieFuture existing = this.requestedCookies.putIfAbsent(id, new CookieFuture(id, future));
        if (existing != null) {
            return existing.future();
        }
        // Hardening end

        this.connection.send(new ClientboundCookieRequestPacket(id));

        return future;
    }

    public boolean handleCookieResponse(ServerboundCookieResponsePacket packet) {
        CookieFuture future = this.requestedCookies.remove(packet.key()); // Hardening - atomic take
        if (future != null) {
            future.future().complete(packet.payload());
            return true;
        }

        return false;
    }

    public boolean isAwaitingCookies() {
        return !this.requestedCookies.isEmpty();
    }

    public record CookieFuture(Identifier key, CompletableFuture<byte[]> future) {
    }
}
