import os
import json
from groq import Groq


def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[AI Error] Missing GROQ_API_KEY in environment variables.")
        return None
    return Groq(api_key=api_key)


def generate_answer_key(question_text):
    """
    Takes the raw text of a questionnaire and uses LLM to generate an Answer Key.
    """
    client = get_groq_client()
    if not client:
        return "Error: Server AI is not configured."

    prompt = f"""
    You are an expert academic teacher's assistant.
    TASK: Solve this questionnaire and create a clear Answer Key.
    QUESTIONNAIRE TEXT:
    {question_text}
    INSTRUCTIONS: Be accurate and concise.
    """

    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error generating key: {str(e)}"


def compute_score(student_answer_text, answer_key_text):
    """
    Compares student answer against the answer key using LLM.
    Returns: (score_integer, feedback_dictionary)
    """
    client = get_groq_client()
    if not client:
        return 0, {"Error": "AI Service Unavailable"}

    prompt = f"""
    You are a strict academic grader.

    Reference Answer Key:
    {answer_key_text}

    Student Submission:
    {student_answer_text}

    TASK:
    1. Compare the student's work to the answer key.
    2. Assign a percentage score (0-100).
    3. Provide brief feedback on Accuracy, Completeness, and Clarity.

    OUTPUT FORMAT (Strict JSON):
    {{
        "score": 85,
        "feedback": {{
            "Accuracy": "...",
            "Completeness": "...",
            "Clarity": "..."
        }}
    }}
    """

    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"}
        )

        result_text = completion.choices[0].message.content
        result_data = json.loads(result_text)

        score = result_data.get("score", 0)
        feedback = result_data.get("feedback", {"General": "No feedback provided."})
        return score, feedback

    except Exception as e:
        print(f"AI Scoring Error: {e}")
        return 0, {"Error": "Grading Failed"}