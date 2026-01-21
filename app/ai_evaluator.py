import os
import json
from groq import Groq

def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key: return None
    return Groq(api_key=api_key)

def generate_answer_key(question_text):
    client = get_groq_client()
    if not client: return "Error: Server AI is not configured."
    prompt = f"Solve and create an Answer Key for:\n{question_text}"
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"

def compute_score(student_text, answer_key):
    client = get_groq_client()
    if not client: return 0, {"Error": "AI unavailable"}
    prompt = f"""
    Compare Student Answer to Answer Key.
    Key: {answer_key}
    Student: {student_text}
    Return STRICT JSON: {{"score": 0-100, "feedback": {{"Accuracy": "...", "Clarity": "..."}}}}
    """
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"}
        )
        data = json.loads(completion.choices[0].message.content)
        return data.get("score", 0), data.get("feedback", {})
    except:
        return 0, {"Error": "Grading failed"}