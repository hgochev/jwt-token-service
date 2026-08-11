package auth

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
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

	fmt.Println("Authenticated user:", result.Status.User.Username)
	fmt.Println("Groups:", result.Status.User.Groups)

	return nil
}
