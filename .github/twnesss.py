import os
import sys
import asyncio
from telegram import Bot
from telegram.constants import ParseMode

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = int(os.environ.get("CHAT_ID"))
MESSAGE_THREAD_ID = int(os.environ.get("MESSAGE_THREAD_ID"))
COMMIT = os.environ.get("COMMIT")

MSG_TEMPLATE = """
{commit}
""".strip()

def get_caption():
    msg = MSG_TEMPLATE.format(commit=COMMIT)
    return COMMIT if len(msg) > 1024 else msg

def check_environ():
    if not BOT_TOKEN:
        print("[-] Invalid BOT_TOKEN")
        exit(1)
    if not CHAT_ID:
        print("[-] Invalid CHAT_ID")
        exit(1)
    if not COMMIT:
        print("[-] Invalid COMMIT")
        exit(1)

async def main():
    print("[+] Uploading to Telegram")
    check_environ()
    files = sys.argv[1:]
    if not files:
        print("[-] No files to upload")
        exit(1)

    print(f"[+] Files to upload: {files}")
    bot = Bot(token=BOT_TOKEN)
    caption = get_caption()

    for i, file_path in enumerate(files):
        if not os.path.exists(file_path):
            print(f"[-] File not found: {file_path}")
            continue
        current_caption = caption if i == len(files) - 1 else None
        try:
            print(f"[+] Sending: {file_path}")
            with open(file_path, "rb") as f:
                await bot.send_document(
                    chat_id=CHAT_ID,
                    document=f,
                    caption=current_caption,
                    message_thread_id=MESSAGE_THREAD_ID,
                    parse_mode=ParseMode.MARKDOWN
                )
        except Exception as e:
            print(f"[-] Failed to send {file_path}: {e}")

    print("[+] All files processed.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"[-] Error occurred: {e}")