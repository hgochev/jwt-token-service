package auth

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func ValidateToken(ctx context.Context, token string) (string, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("failed to create in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := clientset.AuthenticationV1().
		TokenReviews().
		Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("token review failed: %w", err)
	}

	if !result.Status.Authenticated {
		return "", fmt.Errorf("token is not authenticated")
	}

	username := result.Status.User.Username
	if username == "" {
		return "", fmt.Errorf("authenticated user has no username")
	}

	// Kubernetes ServiceAccount usernames have this form:
	// system:serviceaccount:<namespace>:<service-account-name>
	namespace, err := serviceAccountNamespace(username)
	if err != nil {
		return "", err
	}

	subjectAccessReview := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   username,
			Groups: result.Status.User.Groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      "create",
				Group:     "auth.jwt-token-service.io",
				Resource:  "tokens",
			},
		},
	}

	sarResult, err := clientset.AuthorizationV1().
		SubjectAccessReviews().
		Create(ctx, subjectAccessReview, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("subject access review failed: %w", err)
	}

	if !sarResult.Status.Allowed {
		return "", fmt.Errorf("user %q is not authorized to create tokens", username)
	}

	return username, nil
}

func serviceAccountNamespace(username string) (string, error) {
	const prefix = "system:serviceaccount:"

	if len(username) <= len(prefix) || username[:len(prefix)] != prefix {
		return "", fmt.Errorf("authenticated identity %q is not a service account", username)
	}

	remainder := username[len(prefix):]

	for i := 0; i < len(remainder); i++ {
		if remainder[i] == ':' {
			namespace := remainder[:i]

			if namespace == "" {
				return "", fmt.Errorf("service account namespace is empty")
			}

			return namespace, nil
		}
	}

	return "", fmt.Errorf("invalid service account username %q", username)
}
