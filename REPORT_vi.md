# Báo cáo nộp  — Assignment 11 (Tiếng Việt)

**Sinh viên:** Tran Van Huynh

## Tóm tắt ngắn (1 phần)
- Mục tiêu: Xây pipeline phòng thủ nhiều lớp cho trợ lý ngân hàng.
- Trạng thái: Hoàn thành prototype end-to-end và chạy bộ kiểm thử theo đề bài.

## Những gì đã làm (tóm tắt)
- Rate limiter (sliding-window, per-user) — triển khai, stress test 15 requests: 1–10 cho phép, 11–15 bị block.
- Input guardrails: prompt injection detection (regex) và topic filter — triển khai; 7 prompt tấn công mẫu đều bị chặn.
- Output guardrails: PII detection & redaction — triển khai và hoạt động trên ví dụ.
- LLM-as-Judge: có mô-đun chấm đa tiêu chí (SAFETY, RELEVANCE, ACCURACY, TONE). Mặc định dùng heuristic nội bộ; hỗ trợ gọi LLM thực tế nếu bật `USE_LLM_JUDGE=1` và có `OPENAI_API_KEY`.
- Audit log: tất cả tương tác ghi vào `assignment11_audit_log.json` (đã xuất).
- Monitoring: `MonitoringAlert` kiểm tra các ngưỡng và in cảnh báo (có thể mở rộng thành webhook/Prometheus).

## Kết quả kiểm thử (tóm tắt)
- Test1 (Safe queries): tất cả truy vấn an toàn PASS.
- Test2 (Attack queries): 7 prompt tấn công đều bị block.
- Test3 (Rate limiting): hoạt động theo đề (10 pass, 5 blocked).
- Test4 (Edge cases): đã xử lý (empty/long/emoji/SQL-like).

## File nộp (vui lòng kiểm tra)
- `notebooks/lab11_guardrails_hitl.ipynb` — notebook.
- `src/assignment11_defense_pipeline.py` — pipeline đầy đủ + tests.
- `assignment11_audit_log.json` — audit log.
- `PART_B_REPORT_vi.md` — báo cáo Phần B (1–2 trang).
- `FINAL_REPORT_vi.md` — file này (báo cáo nộp ngắn gọn).
---
