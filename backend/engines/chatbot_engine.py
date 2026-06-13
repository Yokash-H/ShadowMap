from transformers import pipeline

print("[SHADOW CHAT] Loading offline LLM (SmolLM2-135M-Instruct)...")
try:
    chat_pipeline = pipeline(
        "text-generation", 
        model="HuggingFaceTB/SmolLM2-135M-Instruct", 
        max_new_tokens=150,
        device="cpu"
    )
    print("[SHADOW CHAT] Model loaded successfully.")
except Exception as e:
    print(f"[SHADOW CHAT] Failed to load offline LLM: {e}")
    chat_pipeline = None

def generate_chat_reply(message: str, context_str: str, history_list: list) -> str:
    """
    Generates a reply using the offline LLM. 
    If it fails, provides a rule-based fallback.
    """
    if chat_pipeline:
        try:
            # Construct a clear prompt using the messages format
            messages = [
                {"role": "system", "content": f"You are Shadow, a cybersecurity assistant. Be concise and helpful. {context_str}"}
            ]
            
            for msg in history_list[-5:]:
                role = "user" if msg.get("role") == "user" else "assistant"
                messages.append({"role": role, "content": msg.get("content", "")})
            
            messages.append({"role": "user", "content": message})
            
            # Generate response with repetition penalty to prevent loop regurgitation
            result = chat_pipeline(
                messages, 
                max_new_tokens=150, 
                temperature=0.7, 
                top_p=0.9,
                repetition_penalty=1.15,
                do_sample=True
            )
            reply = result[0]['generated_text'][-1]['content'].strip()
            
            if not reply:
                raise ValueError("Empty reply generated.")
                
            return reply
            
        except Exception as e:
            import traceback
            err_str = traceback.format_exc()
            print(f"[SHADOW CHAT] Generation error: {e}\n{err_str}", flush=True)
            pass # Fall back to rule-based
            
    # Rule-based fallback if LLM is unavailable or crashes
    msg_lower = message.lower()
    if "phish" in msg_lower:
        return "Phishing is a cyber attack where scammers try to trick you into revealing sensitive information by pretending to be a trustworthy entity. Always verify sender addresses and avoid clicking suspicious links!"
    elif "breach" in msg_lower or "hack" in msg_lower:
        return "A data breach occurs when confidential information is accessed without authorization. If you suspect a breach, immediately change your passwords and enable Two-Factor Authentication (2FA)."
    elif "malware" in msg_lower or "virus" in msg_lower:
        return "Malware is malicious software designed to harm your device or steal data. Keep your antivirus updated and never download attachments from unknown sources."
    elif "password" in msg_lower:
        return "Always use strong, unique passwords for every account. Consider using a reputable password manager and enable Two-Factor Authentication (2FA) wherever possible."
    else:
        return (
            "I'm Shadow, your offline cybersecurity AI! "
            "I can help you understand phishing, malware, data breaches, and privacy risks. "
            "How can I help you secure your digital life today?"
        )
