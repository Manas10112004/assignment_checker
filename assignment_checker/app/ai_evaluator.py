from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

def compute_score(student_answer, answer_key):
    """
    Compute the similarity score between student answer and answer key using cosine similarity.
    Returns a float percentage score (0.0 to 100.0).
    """
    print("[AI_EVALUATOR] compute_score() called.")

    # Validate input
    if not student_answer or not student_answer.strip():
        print("[AI_EVALUATOR] Student answer is empty.")
        return 0.0

    if not answer_key or not answer_key.strip():
        print("[AI_EVALUATOR] Answer key is empty.")
        return 0.0

    # Prepare documents
    print("[AI_EVALUATOR] Preprocessing answers...")
    documents = [student_answer.strip(), answer_key.strip()]

    try:
        vectorizer = TfidfVectorizer(stop_words='english', lowercase=True)
        tfidf_matrix = vectorizer.fit_transform(documents)

        cosine_sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
        score = round(cosine_sim * 100, 2)

        print(f"[AI_EVALUATOR] Cosine Similarity: {cosine_sim:.4f}")
        print(f"[AI_EVALUATOR] Computed Score: {score}%")
        return score

    except Exception as e:
        print(f"[AI_EVALUATOR] Error during scoring: {e}")
        return 0.0
