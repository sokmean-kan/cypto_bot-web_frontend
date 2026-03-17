import os
import base64
import logging
import re
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    Application,
    MessageHandler,
    CommandHandler,
    ConversationHandler,
    filters,
    ContextTypes
)

# ─── Load ENV ─────────────────────────────────────────────
load_dotenv()

BOT_TOKEN       = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED_CHAT_ID = os.getenv("ALLOWED_CHAT_ID")

# ─── Public Keys Map ──────────────────────────────────────
PUBLIC_KEYS = {
    "vandy": os.getenv("PUBLIC_KEY_VANDY"),
    "khema": os.getenv("PUBLIC_KEY_KHEMA"),
    "kun":   os.getenv("PUBLIC_KEY_KUN"),
    "mean":  os.getenv("PUBLIC_KEY_MEAN")
}

# ─── Conversation States ──────────────────────────────────
WAIT_FOR_TEXT = 1
WAIT_FOR_NAME = 2

# ─── Logging ──────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)

# ─── Load Public Key ──────────────────────────────────────
def load_public_key(key_str: str):
    key_str = key_str.strip()
    if "-----BEGIN" not in key_str:
        formatted = "\n".join(
            key_str[i:i+64] for i in range(0, len(key_str), 64)
        )
        key_str = f"-----BEGIN PUBLIC KEY-----\n{formatted}\n-----END PUBLIC KEY-----"
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(key_str.encode(), backend=default_backend())

# ─── Hybrid Encrypt ───────────────────────────────────────
def hybrid_encrypt(plain_text: str, username: str) -> str:
    try:
        key_str = PUBLIC_KEYS.get(username.lower())
        if not key_str:
            return f"❌ No public key found for {username}!"

        public_key = load_public_key(key_str)

        # Step 1 — Generate random AES key and IV
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        # Step 2 — Encrypt plain text with AES
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text.encode("utf-8")) + padder.finalize()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Step 3 — Encrypt AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # ✅ SHA256
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Step 4 — Combine
        combined = (
            base64.b64encode(encrypted_aes_key).decode() + "." +
            base64.b64encode(iv).decode() + "." +
            base64.b64encode(encrypted_data).decode()
        )
        return combined

    except Exception as e:
        return f"❌ Encryption failed: {str(e)}"

# ─── Check Authorization ──────────────────────────────────
def is_authorized(chat_id) -> bool:
    if ALLOWED_CHAT_ID is None:
        return True
    return str(chat_id) == ALLOWED_CHAT_ID

# ─── Keyboard for User Selection ─────────────────────────
def user_keyboard():
    return ReplyKeyboardMarkup(
        [["Vandy", "Khema", "Kun","Mean"]],
        one_time_keyboard=True,
        resize_keyboard=True
    )

# ─── Escape Markdown ──────────────────────────────────────
def escape_markdown(text: str) -> str:
    special_chars = r'\_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(special_chars)}])', r'\\\1', text)

# ─── Handlers ─────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return ConversationHandler.END

    await update.message.reply_text(
        "👋 <b>Welcome to RSA v3 Encrypt Bot!</b>\n\n"
        "Send me any text and I will encrypt it!\n\n"
        "Just type your message to begin 🔒",
        parse_mode="HTML"
    )
    return ConversationHandler.END

# Step 1 — User sends text
async def receive_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return ConversationHandler.END

    context.user_data["text_to_encrypt"] = update.message.text.strip()

    await update.message.reply_text(
        "👤 <b>Who do you want to encrypt for?</b>\n\nChoose a user:",
        parse_mode="HTML",
        reply_markup=user_keyboard()
    )
    return WAIT_FOR_NAME

# Step 2 — User selects name
async def receive_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return ConversationHandler.END

    username = update.message.text.strip().lower()
    text_to_encrypt = context.user_data.get("text_to_encrypt", "")

    if username not in PUBLIC_KEYS:
        await update.message.reply_text(
            f"❌ Unknown user <b>{username}</b>!\n\nChoose: Vandy, Khema, Kun or Mean",
            parse_mode="HTML",
            reply_markup=user_keyboard()
        )
        return WAIT_FOR_NAME

    # ✅ Encrypt Hybrid
    encrypted = hybrid_encrypt(text_to_encrypt, username)
    escaped = escape_markdown(encrypted)

    await update.message.reply_text(
        f"```\n{escaped}\n```",
        parse_mode="MarkdownV2",
        reply_markup=ReplyKeyboardRemove()
    )

    context.user_data.clear()
    return ConversationHandler.END

# Cancel command
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text(
        "❌ Cancelled!",
        reply_markup=ReplyKeyboardRemove()
    )
    return ConversationHandler.END

# Clear messages
async def clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return

    chat_id = update.effective_chat.id
    message_id = update.message.message_id
    deleted = 0

    for i in range(message_id, 0, -1):
        try:
            await context.bot.delete_message(
                chat_id=chat_id,
                message_id=i
            )
            deleted += 1
        except Exception:
            break

    await context.bot.send_message(
        chat_id=chat_id,
        text=f"🧹 Cleared <b>{deleted}</b> messages!",
        parse_mode="HTML"
    )

# ─── Main ─────────────────────────────────────────────────
def main():
    app = Application.builder().token(BOT_TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[
            MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)
        ],
        states={
            WAIT_FOR_NAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_name)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel)]
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(conv_handler)

    print("▶ v3 Encrypt Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()