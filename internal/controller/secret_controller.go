package controller

import (
	"context"
	"time"

	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	domainPrefix = "secret-genie.koalaops.com/"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=geniepatcher.secret-genie.koalaops.com,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=geniepatcher.secret-genie.koalaops.com,resources=secrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=geniepatcher.secret-genie.koalaops.com,resources=secrets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Secret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.0/pkg/reconcile
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx).WithValues("secret", req.NamespacedName)

	// Fetch the Secret instance
	secret := &corev1.Secret{}
	err := r.Get(ctx, req.NamespacedName, secret)
	if err != nil {
		// Error reading the object - requeue the request.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the secret should be patched
	if checkAnnotation(*secret, "patch", "true").IsValid {
		secretIsProcessedAnnotation := checkAnnotation(*secret, "processed", "true")
		secretTypeAnnotation := checkAnnotation(*secret, "type", "")
		// regardless the outcome we marke the secret as processed
		secret.Annotations[domainPrefix+"processed"] = "true"
		// Create user name and password and hash these for basic auth
		if !secretIsProcessedAnnotation.IsValid && secretTypeAnnotation.IsValid && secretTypeAnnotation.Value == "basic-auth" {
			userAnnotation := checkAnnotation(*secret, "basic-auth/username", "")
			user := randomString("abcdefghijklmnopqrstuvwxyz", 12)
			if userAnnotation.IsValid {
				user = userAnnotation.Value
			}
			// generate pass using generateRandomPassword
			pass, err := generateRandomPassword(12)
			if err != nil {
				return reconcile.Result{}, err
			}
			// hash the password
			hashedPassword, err := apacheMD5Hash(pass)
			if err != nil {
				return reconcile.Result{}, err
			}
			// Add the user name and password to the secret
			secret.Data = map[string][]byte{
				"username": []byte(user),
				"password": []byte(pass),
				"auth":     []byte(user + ":" + string(hashedPassword)),
			}
		}

		// Add or update the custom annotation with the current timestamp
		customTimestamp := time.Now().UTC().Format(time.RFC3339) // Format as "2024-03-02T13:43:41Z"
		secret.Annotations[domainPrefix+"processed-at"] = customTimestamp

		err = r.Update(ctx, secret)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

// CheckResult represents the result of checking a specific annotation in a Secret.
type CheckResult struct {
	Exists  bool // Indicates whether the annotation exists
	IsValid bool // Indicates whether the annotation's value is "true"
	Value   string
}

// CheckAnnotation checks if the specified annotation exists and if its value is "true".
func checkAnnotation(secret corev1.Secret, key string, comparer string) CheckResult {
	val, ok := secret.Annotations[domainPrefix+key]
	var IsValid bool
	if comparer == "" {
		IsValid = ok
	} else {
		IsValid = ok && val == comparer
	}
	return CheckResult{
		Exists:  ok,
		IsValid: IsValid,
		Value:   val,
	}
}

func randomString(charset string, length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Function to generate a random string of a specified length
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"!@#$%^&*()_+"

	b := make([]byte, length) // Creating a slice to store the bytes
	_, err := rand.Read(b)    // Generating random bytes
	if err != nil {
		return "", err // Return the error if there is one
	}
	for i := 0; i < length; i++ {
		b[i] = charset[b[i]%byte(len(charset))] // Mapping each byte to a character in the charset
	}
	return string(b), nil // Returning the generated password as a string
}

// Generates an Apache-style MD5 password hash.
func apacheMD5Hash(password string) (string, error) {
	// Generate a random 8-byte salt
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	salt := base64.StdEncoding.EncodeToString(b)[:8]

	// Create a magic prefix and concatenate it with the salt
	magic := "$apr1$"
	saltedMagic := magic + salt

	// Hash the password with the salted magic string
	hash := md5.New()
	io.WriteString(hash, password)
	io.WriteString(hash, saltedMagic)

	// Final hash: combine and format
	finalHash := fmt.Sprintf("%s%s$%x", magic, salt, hash.Sum(nil))

	return finalHash, nil
}
