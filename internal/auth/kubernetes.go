package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func ValidateToken(ctx context.Context, token string) error {
	config, err := rest.InClusterConfig()

	if err != nil {
		return fmt.Errorf("failed to get cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)

	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := clientset.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})

	if err != nil {
		return fmt.Errorf("token review failed: %w", err)
	}

	if !result.Status.Authenticated {
		return fmt.Errorf("invalid token")
	}

	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   result.Status.User.Username,
			Groups: result.Status.User.Groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:    "auth.jwt-tokek-service.io",
				Resource: "tokens",
				Verb:     "create",
			},
		},
	}

	sarResult, err := clientset.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("subject access review failed: %w", err)
	}

	if !sarResult.Status.Allowed {
		return fmt.Errorf("not authorized to create tokens")
	}

	parsedToken, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token claims: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)

	if !ok {
		return fmt.Errorf("Invalid token claims")
	}

	fmt.Println("Authenticated user:", result.Status.User.Username)
	fmt.Println("Groups:", result.Status.User.Groups)
	claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println("Token claims:", string(claimsJSON))

	return nil
}
