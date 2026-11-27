# -*- coding: utf-8 -*-
"""
ChronoVault — الخزنة الزمنية الذكية
تشفير مؤقت للملفات والصور: Camellia-256 + HMAC-SHA256

مشروع مادة التشفير
الجامعة المستنصرية - كلية الهندسة
إشراف: الدكتور حيدر طارش
الطالبة: مريم محمود
"""

import base64
import hmac
import hashlib
import io
import json
import os
import re
import struct
import time
from datetime import datetime

import streamlit as st
from PIL import Image, ImageFilter
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# gTTS اختيارية: إذا لم تتوفر يعمل التطبيق بدون صوت
try:
    from gtts import gTTS
    GTTS_OK = True
except ImportError:
    GTTS_OK = False

# خوارزمية Camellia: المسار يختلف حسب إصدار المكتبة
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
except ImportError:  # الإصدارات الأقدم
    from cryptography.hazmat.primitives.ciphers.algorithms import Camellia


# ============================================================
# 1) الثوابت وبنية الملف المشفّر (بدون أي تغيير عن النسخة السابقة)
# ============================================================
# [MAGIC 5][SALT 16][IV 16][CREATED 8][EXPIRY 8][CIPHERTEXT ...][HMAC 32]
# البصمة HMAC تغطي (الترويسة + النص المشفر) فوقت الانتهاء محمي من التعديل.

MAGIC = b"TXCH1"
SALT_LEN = 16
IV_LEN = 16
TAG_LEN = 32
HEADER_LEN = len(MAGIC) + SALT_LEN + IV_LEN + 8 + 8
PBKDF2_ITERATIONS = 200_000
TTS_MAX_CHARS = 1500  # حد أقصى للنص المنطوق حتى يبقى الصوت سريعاً


# ============================================================
# 2) الاستثناءات المخصصة
# ============================================================
class ExpiredError(Exception):
    """انتهت صلاحية الملف."""


class TamperError(Exception):
    """فشل التحقق من HMAC: تلاعب بالبيانات أو كلمة مرور خاطئة."""


class FormatError(Exception):
    """الملف ليس بصيغة النظام."""


# ============================================================
# 3) الدوال التشفيرية
# ============================================================
def derive_keys(password: str, salt: bytes):
    """اشتقاق مفتاحين مستقلين من كلمة المرور (PBKDF2-SHA256):
    - 32 بايت (256 بت) لتشفير Camellia-256
    - 32 بايت لبصمة HMAC-SHA256
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    material = kdf.derive(password.encode("utf-8"))
    return material[:32], material[32:]


def compute_hmac(mac_key: bytes, data: bytes) -> bytes:
    """توليد البصمة الرقمية HMAC-SHA256."""
    return hmac.new(mac_key, data, hashlib.sha256).digest()


def encrypt_data(data: bytes, meta: dict, password: str, expiry_ts: int) -> bytes:
    """تشفير البيانات مع البيانات الوصفية ووقت الانتهاء."""
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    enc_key, mac_key = derive_keys(password, salt)

    meta_bytes = json.dumps(meta, ensure_ascii=False).encode("utf-8")
    payload = struct.pack(">I", len(meta_bytes)) + meta_bytes + data

    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(Camellia(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    created_ts = int(time.time())
    header = MAGIC + salt + iv + struct.pack(">QQ", created_ts, expiry_ts)

    # التشفير ثم التوقيع (Encrypt-then-MAC)
    tag = compute_hmac(mac_key, header + ciphertext)
    return header + ciphertext + tag


def decrypt_data(blob: bytes, password: str, log=None):
    """فك التشفير بالترتيب الآمن:
    1) فحص الصيغة  2) التحقق من HMAC  3) التحقق من الوقت  4) فك التشفير
    """

    def say(msg):
        if log:
            log(msg)

    say("فحص صيغة الملف...")
    if len(blob) < HEADER_LEN + 16 + TAG_LEN or blob[: len(MAGIC)] != MAGIC:
        raise FormatError("الملف ليس بصيغة النظام.")

    pos = len(MAGIC)
    salt = blob[pos: pos + SALT_LEN]
    pos += SALT_LEN
    iv = blob[pos: pos + IV_LEN]
    pos += IV_LEN
    created_ts, expiry_ts = struct.unpack(">QQ", blob[pos: pos + 16])

    header = blob[:HEADER_LEN]
    ciphertext = blob[HEADER_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]

    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise TamperError("طول النص المشفر غير صالح.")

    say("اشتقاق المفاتيح من كلمة المرور...")
    enc_key, mac_key = derive_keys(password, salt)

    # الخطوة 1: التحقق من البصمة (مقارنة بزمن ثابت)
    say("جاري التحقق من البصمة الرقمية (HMAC-SHA256)...")
    expected = compute_hmac(mac_key, header + ciphertext)
    if not hmac.compare_digest(expected, tag):
        raise TamperError("فشل التحقق من البصمة.")
    say("الملف سليم ✔ (البصمة مطابقة)")

    # الخطوة 2: التحقق من الوقت (القيمة محمية بالبصمة)
    say("جاري التحقق من صلاحية الوقت...")
    if expiry_ts != 0 and time.time() > expiry_ts:
        raise ExpiredError(expiry_ts)
    say("الصلاحية سارية ✔")

    # الخطوة 3: فك التشفير
    say("جاري فك التشفير (Camellia-256)...")
    cipher = Cipher(Camellia(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        payload = unpadder.update(padded) + unpadder.finalize()
        meta_len = struct.unpack(">I", payload[:4])[0]
        meta = json.loads(payload[4: 4 + meta_len].decode("utf-8"))
        data = payload[4 + meta_len:]
    except Exception:
        raise TamperError("تعذّر قراءة البيانات بعد فك التشفير.")

    return data, meta, created_ts, expiry_ts


# ============================================================
# 4) دوال مساعدة: الوقت، الصوت، تآكل الصورة
# ============================================================
def fmt_ts(ts: int) -> str:
    """تنسيق الطابع الزمني."""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def fmt_remaining(seconds: float) -> str:
    """تحويل الثواني المتبقية إلى نص عربي مقروء."""
    s = int(max(0, seconds))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = []
    if d:
        parts.append(f"{d} يوم")
    if h:
        parts.append(f"{h} ساعة")
    if m:
        parts.append(f"{m} دقيقة")
    if s or not parts:
        parts.append(f"{s} ثانية")
    return " و ".join(parts)


def detect_lang(text: str) -> str:
    """اكتشاف اللغة تلقائياً: عربي إذا كانت أغلب الحروف عربية، وإلا إنجليزي."""
    arabic = len(re.findall(r"[\u0600-\u06FF]", text))
    letters = len(re.findall(r"[A-Za-z\u0600-\u06FF]", text))
    if letters and arabic / letters > 0.3:
        return "ar"
    return "en"


def tts_bytes(text: str, lang: str) -> bytes:
    """تحويل النص إلى صوت (MP3) في الذاكرة عبر BytesIO.
    ملاحظة: لا نستخدم الكاش هنا حتى لا يُحفظ النص المفكوك في الذاكرة المؤقتة."""
    buf = io.BytesIO()
    gTTS(text=text[:TTS_MAX_CHARS], lang=lang).write_to_fp(buf)
    return buf.getvalue()


@st.cache_data(show_spinner=False, max_entries=8)
def refusal_audio(kind: str):
    """صوت قصير لعبارة الرفض (عبارات ثابتة لذلك يجوز تخزينها مؤقتاً)."""
    phrase = "انتهت الصلاحية" if kind == "expired" else "تم كشف التلاعب بالبيانات"
    return tts_bytes(phrase, "ar")


def play_audio(audio_bytes: bytes, autoplay: bool = True):
    """عرض مشغل الصوت مع محاولة التشغيل التلقائي."""
    try:
        st.audio(audio_bytes, format="audio/mp3", autoplay=autoplay)
    except TypeError:  # إصدار قديم لا يدعم autoplay
        st.audio(audio_bytes, format="audio/mp3")


def decay_image(img: Image.Image, remaining_ratio: float) -> Image.Image:
    """التآكل التدريجي: كلما قلّ الوقت المتبقي زاد التمويه والتبكسل.
    remaining_ratio = 1 (صورة سليمة)  →  0 (أقصى تشويه)."""
    d = 1.0 - max(0.0, min(1.0, remaining_ratio))  # درجة التشويه 0..1
    if d < 0.02:
        return img
    w, h = img.size
    out = img
    # 1) تمويه يزداد مع الزمن
    blur = d * 4
    if blur > 0.3:
        out = out.filter(ImageFilter.GaussianBlur(blur))
    # 2) تبكسل: حجم المربع يكبر تدريجياً
    block = int(1 + (d ** 1.6) * (min(w, h) / 5))
    if block > 1:
        small = out.resize((max(1, w // block), max(1, h // block)), Image.Resampling.BILINEAR)
        out = small.resize((w, h), Image.Resampling.NEAREST)
    return out


def make_preview(data: bytes):
    """فتح الصورة وتصغيرها (لتسريع التحديث كل ثانية). يرجع None إن لم تكن صورة."""
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        img = img.convert("RGB")
        img.thumbnail((900, 900))
        return img
    except Exception:
        return None


# ============================================================
# 5) الإعدادات العامة والتنسيق
# ============================================================
st.set_page_config(page_title="ChronoVault", page_icon="🔐", layout="centered")

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap');
html, body, [class*="css"], .stApp { font-family: 'Cairo', sans-serif; direction: rtl; text-align: right; }
.stTabs [data-baseweb="tab-list"] { gap: 8px; justify-content: center; }
.stTabs [data-baseweb="tab"] { font-weight: 700; font-size: 1.05rem; }
.stTextInput input, .stTextArea textarea, .stNumberInput input { direction: rtl; text-align: right; }

.header-box {
    border: 1px solid #c9d6e6; border-radius: 16px; padding: 14px 10px; margin-bottom: 14px;
    background: linear-gradient(135deg, #f4f8fc 0%, #e4edf7 100%); color: #1f3a5f;
}
.header-table { width: 100%; border-collapse: collapse; }
.header-table td { vertical-align: middle; text-align: center; }
.logo-img { width: 84px; height: 84px; object-fit: contain; }
.logo-ph {
    width: 84px; height: 84px; border-radius: 50%; border: 2px dashed #8aa3c2;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 0.7rem; color: #5b7ba3; padding: 6px; box-sizing: border-box;
}
.uni { font-size: 1.25rem; font-weight: 700; margin: 0; }
.college { font-size: 1rem; font-weight: 600; margin: 2px 0 6px 0; }
.people { font-size: 0.92rem; line-height: 1.8; margin: 0; }

.brand { text-align: center; margin: 6px 0 2px 0; }
.brand h1 {
    font-size: 2.3rem; margin: 0; letter-spacing: 1px; direction: ltr;
    background: linear-gradient(90deg, #2b6cb0, #2e8b72);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.brand p { color: #5a6b7d; margin: 2px 0 14px 0; }

.card { border-radius: 14px; padding: 12px 16px; margin: 10px 0; border-right: 6px solid; }
.card b { display: block; margin-bottom: 4px; }
.card-ok   { background: #eaf6f1; border-color: #2e8b72; color: #1d5c4a; }
.card-warn { background: #fdf5e3; border-color: #d9a441; color: #7a5a14; }
.card-bad  { background: #fbeceb; border-color: #c8553d; color: #7d2e1f; }
.card-info { background: #eaf1fa; border-color: #2b6cb0; color: #1f4673; }
.bar-wrap { background: #e3e9f0; border-radius: 10px; height: 14px; overflow: hidden; margin-top: 8px; }
.bar-fill { height: 100%; border-radius: 10px; transition: width 0.5s; }
</style>
""",
    unsafe_allow_html=True,
)


def card(kind: str, title: str, body: str, ratio=None, bar_color=None):
    """بطاقة حالة ملونة، مع شريط تقدم اختياري."""
    bar = ""
    if ratio is not None:
        pct = int(max(0, min(1, ratio)) * 100)
        bar = (
            f'<div class="bar-wrap"><div class="bar-fill" '
            f'style="width:{pct}%; background:{bar_color};"></div></div>'
        )
    st.markdown(f'<div class="card card-{kind}"><b>{title}</b>{body}{bar}</div>', unsafe_allow_html=True)


# ============================================================
# 6) الشريط الجانبي (Sidebar)
# ============================================================
def load_logo_b64(candidates):
    """البحث عن ملف الشعار بجوار app.py أو داخل مجلد assets."""
    base = os.path.dirname(os.path.abspath(__file__))
    for folder in (base, os.path.join(base, "assets")):
        for name in candidates:
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    ext = name.rsplit(".", 1)[-1].lower()
                    mime = "image/jpeg" if ext in ("jpg", "jpeg") else f"image/{ext}"
                    return f"data:{mime};base64," + base64.b64encode(f.read()).decode()
    return None


def uploaded_to_uri(up):
    if up is None:
        return None
    ext = up.name.rsplit(".", 1)[-1].lower()
    mime = "image/jpeg" if ext in ("jpg", "jpeg") else f"image/{ext}"
    return f"data:{mime};base64," + base64.b64encode(up.getvalue()).decode()


def logo_html(data_uri, placeholder_text):
    if data_uri:
        return f'<img class="logo-img" src="{data_uri}" />'
    return f'<div class="logo-ph">{placeholder_text}</div>'


with st.sidebar:
    st.markdown("## 🔐 ChronoVault")
    st.caption("الخزنة الزمنية الذكية")
    st.markdown("**👩‍🎓 الطالبة:** مريم محمود")
    st.markdown("**👨‍🏫 المشرف:** د. حيدر طارش")
    st.markdown("---")
    st.markdown("### 🧭 خطوات العمل")
    st.markdown(
        """
1. **اختاري** نصاً أو صورة أو ملفاً.
2. **أدخلي** كلمة المرور وحدّدي المؤقت.
3. **حمّلي** الملف المشفّر (Camellia-256 + HMAC).
4. عند الفك يُفحص **الـ HMAC** ثم **الوقت**.
5. عند النجاح يظهر المحتوى، والنص يُقرأ بصوت طبيعي، والصورة **تتآكل** مع الوقت.
"""
    )
    st.markdown("---")
    speak_refusal = st.toggle("🔊 نطق رسالة الرفض صوتياً", value=False, key="speak_refusal")
    if not GTTS_OK:
        st.warning("مكتبة gTTS غير مثبتة، الميزة الصوتية معطّلة.")
    with st.expander("🖼️ شعارات الجامعة والكلية"):
        st.caption("ضعي الملفين بجوار app.py باسم uni_logo.png و college_logo.png، أو ارفعيهما هنا.")
        up_uni = st.file_uploader("شعار الجامعة المستنصرية", type=["png", "jpg", "jpeg"], key="up_uni")
        up_col = st.file_uploader("شعار كلية الهندسة", type=["png", "jpg", "jpeg"], key="up_col")

uni_uri = uploaded_to_uri(up_uni) or load_logo_b64(["uni_logo.png", "uni_logo.jpg", "uni_logo.jpeg"])
col_uri = uploaded_to_uri(up_col) or load_logo_b64(["college_logo.png", "college_logo.jpg", "college_logo.jpeg"])


# ============================================================
# 7) الترويسة (الجامعة، الكلية، الطالبة، المشرف، الشعارات)
# ============================================================
st.markdown(
    f"""
<div class="header-box">
  <table class="header-table">
    <tr>
      <td style="width:20%">{logo_html(uni_uri, "شعار الجامعة")}</td>
      <td style="width:60%">
        <p class="uni">الجامعة المستنصرية</p>
        <p class="college">كلية الهندسة</p>
        <p class="people">
          <b>الطالبة:</b> مريم محمود<br>
          <b>الدكتور المشرف:</b> حيدر طارش
        </p>
      </td>
      <td style="width:20%">{logo_html(col_uri, "شعار الكلية")}</td>
    </tr>
  </table>
</div>
<div class="brand">
  <h1>🔐 ChronoVault</h1>
  <p>الخزنة الزمنية الذكية — تشفير مؤقت يحمي ملفاتك وصورك ثم يغلقها في الوقت المحدد</p>
</div>
""",
    unsafe_allow_html=True,
)

st.session_state.setdefault("enc_result", None)
st.session_state.setdefault("dec_result", None)

tab_enc, tab_dec = st.tabs(["🔒 التشفير", "🔓 فك التشفير"])


# ============================================================
# 8) تبويب التشفير
# ============================================================
with tab_enc:
    st.subheader("عملية التشفير")

    mode = st.radio("نوع البيانات", ["نص", "ملف / صورة"], horizontal=True, key="enc_mode")

    plain_text = ""
    uploaded = None
    if mode == "نص":
        plain_text = st.text_area("أدخلي النص المراد تشفيره", height=140, key="enc_text")
    else:
        uploaded = st.file_uploader(
            "اختاري الملف أو الصورة (PNG / JPG وغيرها)", key="enc_file"
        )
        if uploaded is not None and (uploaded.type or "").startswith("image/"):
            st.image(uploaded, caption="معاينة الصورة الأصلية", width=220)

    c1, c2 = st.columns(2)
    with c1:
        pw1 = st.text_input("كلمة المرور", type="password", key="enc_pw1")
    with c2:
        pw2 = st.text_input("تأكيد كلمة المرور", type="password", key="enc_pw2")

    st.markdown("**⏱️ المؤقت الزمني لانتهاء الصلاحية**")
    use_timer = st.checkbox("تفعيل المؤقت", value=True, key="enc_timer_on")
    unit = "دقيقة"
    amount = 0
    if use_timer:
        t1, t2 = st.columns(2)
        with t1:
            amount = st.number_input("المدة", min_value=1, value=30, step=1, key="enc_amount")
        with t2:
            unit = st.selectbox("الوحدة", ["ثانية", "دقيقة", "ساعة", "يوم"], index=0, key="enc_unit")
        st.caption("نصيحة للعرض المباشر: جرّبي 30 أو 60 ثانية لتري تآكل الصورة بوضوح.")

    if st.button("🔒 تشفير", type="primary", use_container_width=True, key="enc_btn"):
        st.session_state["enc_result"] = None

        if mode == "نص" and not plain_text.strip():
            st.error("⛔ الرجاء إدخال نص للتشفير.")
        elif mode != "نص" and uploaded is None:
            st.error("⛔ الرجاء اختيار ملف للتشفير.")
        elif len(pw1) < 6:
            st.error("⛔ كلمة المرور يجب ألا تقل عن 6 أحرف.")
        elif pw1 != pw2:
            st.error("⛔ كلمتا المرور غير متطابقتين.")
        else:
            with st.status("جاري التشفير...", expanded=True) as status:
                try:
                    st.write("تجهيز البيانات...")
                    if mode == "نص":
                        data = plain_text.encode("utf-8")
                        meta = {"kind": "text", "name": "message.txt", "mime": "text/plain"}
                    else:
                        data = uploaded.getvalue()
                        meta = {
                            "kind": "file",
                            "name": uploaded.name,
                            "mime": uploaded.type or "application/octet-stream",
                        }

                    st.write("حساب وقت الانتهاء...")
                    if use_timer:
                        mult = {"ثانية": 1, "دقيقة": 60, "ساعة": 3600, "يوم": 86400}[unit]
                        expiry_ts = int(time.time() + amount * mult)
                    else:
                        expiry_ts = 0

                    st.write("اشتقاق المفاتيح (PBKDF2-SHA256)...")
                    st.write("جاري التشفير بخوارزمية Camellia-256...")
                    st.write("جاري توليد البصمة الرقمية HMAC-SHA256...")
                    blob = encrypt_data(data, meta, pw1, expiry_ts)

                    st.session_state["enc_result"] = {
                        "blob": blob,
                        "name": meta["name"],
                        "expiry": expiry_ts,
                    }
                    status.update(label="تم التشفير بنجاح ✔", state="complete")
                    st.toast("تم التشفير وتوليد البصمة الرقمية", icon="🔒")
                except Exception as e:
                    status.update(label="فشل التشفير", state="error")
                    st.error(f"حدث خطأ أثناء التشفير: {e}")

    res = st.session_state["enc_result"]
    if res:
        if res["expiry"]:
            card("ok", "✅ تم التشفير بنجاح",
                 f"البصمة الرقمية جاهزة. ⏳ تنتهي الصلاحية في: <b style='display:inline'>{fmt_ts(res['expiry'])}</b>")
        else:
            card("info", "✅ تم التشفير بنجاح", "♾️ لا يوجد مؤقت: الملف بدون تاريخ انتهاء.")

        st.download_button(
            "⬇️ تحميل الملف المشفّر (.txch)",
            data=res["blob"],
            file_name=res["name"] + ".txch",
            mime="application/octet-stream",
            use_container_width=True,
            key="enc_download",
        )
        with st.expander("نسخة نصية (Base64) للنسخ واللصق"):
            st.code(base64.b64encode(res["blob"]).decode(), language=None)


# ============================================================
# 9) تبويب فك التشفير
# ============================================================
def wipe_after_expiry(out: dict):
    """عند انتهاء الوقت أثناء العرض: نمسح البيانات الصريحة من الذاكرة
    ونحتفظ فقط بنسخة الصورة بأقصى درجة تشويه."""
    if out.get("preview") is not None:
        out["final_image"] = decay_image(out["preview"], 0.0)
    out["data"] = b""
    out["text"] = None
    out["audio"] = None
    out["preview"] = None
    out["expired"] = True


def live_panel():
    """لوحة العرض الحي: بطاقة المؤقت + الصورة المتآكلة.
    تُحدَّث كل ثانية عبر st.fragment(run_every=1) بدون إعادة تحميل الصفحة."""
    out = st.session_state.get("dec_result")
    if not out or out["expired"]:
        return

    exp = out["expiry"]
    now = time.time()

    if exp == 0:
        card("info", "♾️ بدون مؤقت", "هذا الملف ليس له تاريخ انتهاء.")
        ratio = 1.0
    else:
        if now >= exp:  # انتهى الوقت أثناء المشاهدة
            wipe_after_expiry(out)
            st.rerun()  # إعادة رسم الصفحة كاملة لإخفاء النص والصوت
        total = max(1, exp - out["created"])
        ratio = (exp - now) / total
        if ratio > 0.5:
            kind, color, label = "ok", "#2e8b72", "الصلاحية سارية"
        elif ratio > 0.2:
            kind, color, label = "warn", "#d9a441", "الوقت يقترب من النهاية"
        else:
            kind, color, label = "bad", "#c8553d", "الصلاحية على وشك الانتهاء"
        card(kind, f"⏳ {label}",
             f"المتبقي: {fmt_remaining(exp - now)} ({int(ratio * 100)}%)",
             ratio=ratio, bar_color=color)

    if out.get("preview") is not None:
        st.image(decay_image(out["preview"], ratio),
                 caption="الصورة تتآكل تدريجياً مع اقتراب انتهاء الصلاحية",
                 use_container_width=True)


with tab_dec:
    st.subheader("عملية فك التشفير")

    src = st.radio("مصدر البيانات المشفرة", ["رفع ملف (.txch)", "لصق نص Base64"],
                   horizontal=True, key="dec_src")

    enc_file = None
    enc_text = ""
    if src.startswith("رفع"):
        enc_file = st.file_uploader("اختاري الملف المشفّر", key="dec_file")
    else:
        enc_text = st.text_area("الصقي النص المشفّر (Base64)", height=140, key="dec_text")

    dec_pw = st.text_input("كلمة المرور", type="password", key="dec_pw")

    if st.button("🔓 فك التشفير", type="primary", use_container_width=True, key="dec_btn"):
        st.session_state["dec_result"] = None

        blob = None
        if src.startswith("رفع"):
            if enc_file is None:
                st.error("⛔ الرجاء اختيار الملف المشفّر.")
            else:
                blob = enc_file.getvalue()
        else:
            if not enc_text.strip():
                st.error("⛔ الرجاء لصق النص المشفّر.")
            else:
                try:
                    blob = base64.b64decode(enc_text.strip(), validate=True)
                except Exception:
                    st.error("⛔ النص الملصوق ليس Base64 صالحاً.")

        if blob is not None:
            if not dec_pw:
                st.error("⛔ الرجاء إدخال كلمة المرور.")
            else:
                refusal_kind = None  # "expired" أو "tamper" عند الرفض
                with st.status("جاري المعالجة...", expanded=True) as status:
                    try:
                        data, meta, created_ts, expiry_ts = decrypt_data(
                            blob, dec_pw, log=lambda m: st.write(m)
                        )

                        # تجهيز النتيجة: نص، أو صورة (معاينة للتآكل)، أو ملف عادي
                        result = {
                            "data": data, "meta": meta,
                            "created": created_ts, "expiry": expiry_ts,
                            "expired": False, "text": None, "preview": None,
                            "audio": None, "audio_shown": False, "final_image": None,
                        }
                        if meta.get("kind") == "text":
                            try:
                                result["text"] = data.decode("utf-8")
                            except UnicodeDecodeError:
                                result["text"] = None
                        elif str(meta.get("mime", "")).startswith("image/"):
                            result["preview"] = make_preview(data)

                        # القراءة الصوتية للنص بعد التحقق الناجح (gTTS في الذاكرة)
                        if result["text"] and GTTS_OK:
                            st.write("جاري تحويل النص إلى صوت...")
                            try:
                                lang = detect_lang(result["text"])
                                result["audio"] = tts_bytes(result["text"], lang)
                            except Exception:
                                st.write("تعذّر توليد الصوت (تحتاج gTTS إلى اتصال بالإنترنت).")

                        st.session_state["dec_result"] = result
                        status.update(label="تم فك التشفير بنجاح ✔", state="complete")
                        st.toast("تم فك التشفير ضمن الوقت المحدد 🎉", icon="🔓")
                        st.balloons()
                    except ExpiredError as e:
                        status.update(label="تم رفض الوصول", state="error")
                        refusal_kind = "expired"
                        card("bad", "⛔ تم انتهاء الصلاحية",
                             f"انتهى الوقت المحدد ({fmt_ts(int(e.args[0]))}). تم رفض فك التشفير وحجب المحتوى.")
                    except TamperError:
                        status.update(label="تم رفض الوصول", state="error")
                        refusal_kind = "tamper"
                        card("bad", "🚨 تم كشف التلاعب بالبيانات",
                             "فشلت البصمة الرقمية: قد يكون الملف معدّلاً أو كلمة المرور غير صحيحة. تم رفض فك التشفير.")
                    except FormatError as e:
                        status.update(label="تم رفض الوصول", state="error")
                        st.error(f"⛔ {e}")
                    except Exception as e:
                        status.update(label="تم رفض الوصول", state="error")
                        st.error(f"⛔ خطأ غير متوقع: {e}")

                # نطق عبارة الرفض القصيرة (اختياري من الشريط الجانبي)
                if refusal_kind and speak_refusal and GTTS_OK:
                    try:
                        play_audio(refusal_audio(refusal_kind), autoplay=True)
                    except Exception:
                        pass

    # ---------- عرض النتيجة (يبقى ظاهراً بين إعادات التشغيل) ----------
    out = st.session_state["dec_result"]
    if out:
        if out["expired"]:
            # حالة: انتهى الوقت أثناء العرض → لا نص ولا صوت ولا تحميل
            card("bad", "⛔ تم انتهاء الصلاحية",
                 "انتهى الوقت أثناء العرض، وتم حجب المحتوى ومسحه من الذاكرة.")
            if out.get("final_image") is not None:
                st.image(out["final_image"], caption="الصورة في أقصى درجات التشويه",
                         use_container_width=True)
        else:
            card("ok", "✅ الملف سليم والصلاحية سارية",
                 f"تاريخ التشفير: {fmt_ts(out['created'])}")

            # بطاقة المؤقت + الصورة المتآكلة (تتحدث كل ثانية)
            live = st.fragment(live_panel, run_every=1 if out["expiry"] else None)
            live()

            # النص + الصوت (خارج الـ fragment حتى لا يُعاد تشغيل الصوت كل ثانية)
            out = st.session_state["dec_result"]  # قد تكون تغيرت عند الانتهاء
            if out and not out["expired"]:
                if out["text"] is not None:
                    st.text_area("النص بعد فك التشفير", value=out["text"], height=160, key="dec_out_text")
                    if out["audio"]:
                        st.markdown("🔊 **القراءة الصوتية**")
                        play_audio(out["audio"], autoplay=not out["audio_shown"])
                        out["audio_shown"] = True  # لا نعيد التشغيل التلقائي عند إعادة الرسم
                elif out["meta"].get("kind") == "text":
                    st.warning("تعذّر عرض النص.")

                st.download_button(
                    "⬇️ تحميل الملف بعد فك التشفير",
                    data=out["data"],
                    file_name=out["meta"].get("name", "decrypted_file"),
                    mime=out["meta"].get("mime", "application/octet-stream"),
                    use_container_width=True,
                    key="dec_download",
                )

st.markdown("---")
st.caption("ChronoVault — مشروع مادة التشفير | الجامعة المستنصرية / كلية الهندسة")
