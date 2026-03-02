//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type accountRepoStubForBulkUpdate struct {
	accountRepoStub
	bulkUpdateErr           error
	bulkUpdateIDs           []int64
	bindGroupErrByID        map[int64]error
	removeCredentialErrByID map[int64]error
	removedModelMappingIDs  []int64
	removedModelMappingByID map[int64]int
	accountsByID            map[int64]*Account
}

func (s *accountRepoStubForBulkUpdate) BulkUpdate(_ context.Context, ids []int64, _ AccountBulkUpdate) (int64, error) {
	s.bulkUpdateIDs = append([]int64{}, ids...)
	if s.bulkUpdateErr != nil {
		return 0, s.bulkUpdateErr
	}
	return int64(len(ids)), nil
}

func (s *accountRepoStubForBulkUpdate) BindGroups(_ context.Context, accountID int64, _ []int64) error {
	if err, ok := s.bindGroupErrByID[accountID]; ok {
		return err
	}
	return nil
}

func (s *accountRepoStubForBulkUpdate) GetByIDs(_ context.Context, ids []int64) ([]*Account, error) {
	accounts := make([]*Account, 0, len(ids))
	for _, id := range ids {
		account, ok := s.accountsByID[id]
		if !ok {
			return nil, errors.New("account not found")
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (s *accountRepoStubForBulkUpdate) RemoveCredentialKey(_ context.Context, id int64, key string) error {
	if key != "model_mapping" {
		return errors.New("unexpected credential key")
	}
	s.removedModelMappingIDs = append(s.removedModelMappingIDs, id)
	if s.removedModelMappingByID == nil {
		s.removedModelMappingByID = make(map[int64]int)
	}
	s.removedModelMappingByID[id]++
	if err, ok := s.removeCredentialErrByID[id]; ok {
		return err
	}
	return nil
}

// TestAdminService_BulkUpdateAccounts_AllSuccessIDs 验证批量更新成功时返回 success_ids/failed_ids。
func TestAdminService_BulkUpdateAccounts_AllSuccessIDs(t *testing.T) {
	repo := &accountRepoStubForBulkUpdate{}
	svc := &adminServiceImpl{accountRepo: repo}

	schedulable := true
	input := &BulkUpdateAccountsInput{
		AccountIDs:  []int64{1, 2, 3},
		Schedulable: &schedulable,
	}

	result, err := svc.BulkUpdateAccounts(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, 3, result.Success)
	require.Equal(t, 0, result.Failed)
	require.ElementsMatch(t, []int64{1, 2, 3}, result.SuccessIDs)
	require.Empty(t, result.FailedIDs)
	require.Len(t, result.Results, 3)
}

// TestAdminService_BulkUpdateAccounts_PartialFailureIDs 验证部分失败时 success_ids/failed_ids 正确。
func TestAdminService_BulkUpdateAccounts_PartialFailureIDs(t *testing.T) {
	repo := &accountRepoStubForBulkUpdate{
		bindGroupErrByID: map[int64]error{
			2: errors.New("bind failed"),
		},
	}
	svc := &adminServiceImpl{accountRepo: repo}

	groupIDs := []int64{10}
	schedulable := false
	input := &BulkUpdateAccountsInput{
		AccountIDs:            []int64{1, 2, 3},
		GroupIDs:              &groupIDs,
		Schedulable:           &schedulable,
		SkipMixedChannelCheck: true,
	}

	result, err := svc.BulkUpdateAccounts(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, 2, result.Success)
	require.Equal(t, 1, result.Failed)
	require.ElementsMatch(t, []int64{1, 3}, result.SuccessIDs)
	require.ElementsMatch(t, []int64{2}, result.FailedIDs)
	require.Len(t, result.Results, 3)
}

func TestAdminService_BatchRestoreAccountDefaultModelMapping_AllSuccess(t *testing.T) {
	repo := &accountRepoStubForBulkUpdate{}
	svc := &adminServiceImpl{accountRepo: repo}

	result, err := svc.BatchRestoreAccountDefaultModelMapping(context.Background(), []int64{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, 3, result.Success)
	require.Equal(t, 0, result.Failed)
	require.ElementsMatch(t, []int64{1, 2, 3}, result.SuccessIDs)
	require.Empty(t, result.FailedIDs)
	require.Len(t, result.Results, 3)
	require.Equal(t, []int64{1, 2, 3}, repo.removedModelMappingIDs)
}

func TestAdminService_BatchRestoreAccountDefaultModelMapping_PartialFailureAndDedup(t *testing.T) {
	repo := &accountRepoStubForBulkUpdate{
		removeCredentialErrByID: map[int64]error{2: errors.New("not found")},
	}
	svc := &adminServiceImpl{accountRepo: repo}

	result, err := svc.BatchRestoreAccountDefaultModelMapping(context.Background(), []int64{1, 2, 2, 3, 0, -1})
	require.NoError(t, err)
	require.Equal(t, 2, result.Success)
	require.Equal(t, 1, result.Failed)
	require.ElementsMatch(t, []int64{1, 3}, result.SuccessIDs)
	require.ElementsMatch(t, []int64{2}, result.FailedIDs)
	require.Len(t, result.Results, 3)
	require.Equal(t, []int64{1, 2, 3}, repo.removedModelMappingIDs)
	require.Equal(t, 1, repo.removedModelMappingByID[2])
}

func TestAdminService_BulkUpdateAccounts_ModelMappingEditRequiresSamePlatformAndMapping(t *testing.T) {
	t.Run("allows edit when platform and mapping are identical", func(t *testing.T) {
		repo := &accountRepoStubForBulkUpdate{
			accountsByID: map[int64]*Account{
				1: {
					ID:       1,
					Platform: PlatformAnthropic,
					Credentials: map[string]any{
						"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-sonnet-4-6"},
					},
				},
				2: {
					ID:       2,
					Platform: PlatformAnthropic,
					Credentials: map[string]any{
						"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-sonnet-4-6"},
					},
				},
			},
		}
		svc := &adminServiceImpl{accountRepo: repo}

		input := &BulkUpdateAccountsInput{
			AccountIDs: []int64{1, 2},
			Credentials: map[string]any{
				"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-sonnet-4-6"},
			},
			EditExistingModelMapping: true,
		}

		result, err := svc.BulkUpdateAccounts(context.Background(), input)
		require.NoError(t, err)
		require.Equal(t, 2, result.Success)
		require.Equal(t, []int64{1, 2}, repo.bulkUpdateIDs)
	})

	t.Run("rejects edit when platforms differ", func(t *testing.T) {
		repo := &accountRepoStubForBulkUpdate{
			accountsByID: map[int64]*Account{
				1: {ID: 1, Platform: PlatformAnthropic, Credentials: map[string]any{"model_mapping": map[string]any{"a": "a"}}},
				2: {ID: 2, Platform: PlatformOpenAI, Credentials: map[string]any{"model_mapping": map[string]any{"a": "a"}}},
			},
		}
		svc := &adminServiceImpl{accountRepo: repo}

		_, err := svc.BulkUpdateAccounts(context.Background(), &BulkUpdateAccountsInput{
			AccountIDs: []int64{1, 2},
			Credentials: map[string]any{
				"model_mapping": map[string]any{"a": "b"},
			},
			EditExistingModelMapping: true,
		})

		require.Error(t, err)
		require.ErrorContains(t, err, "same platform")
	})

	t.Run("rejects edit when existing mappings differ", func(t *testing.T) {
		repo := &accountRepoStubForBulkUpdate{
			accountsByID: map[int64]*Account{
				1: {ID: 1, Platform: PlatformAnthropic, Credentials: map[string]any{"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-sonnet-4-6"}}},
				2: {ID: 2, Platform: PlatformAnthropic, Credentials: map[string]any{"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-opus-4-6"}}},
			},
		}
		svc := &adminServiceImpl{accountRepo: repo}

		_, err := svc.BulkUpdateAccounts(context.Background(), &BulkUpdateAccountsInput{
			AccountIDs: []int64{1, 2},
			Credentials: map[string]any{
				"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-sonnet-4-6"},
			},
			EditExistingModelMapping: true,
		})

		require.Error(t, err)
		require.ErrorContains(t, err, "same existing mapping")
	})

	t.Run("does not enforce same mapping when strict edit flag is off", func(t *testing.T) {
		repo := &accountRepoStubForBulkUpdate{
			accountsByID: map[int64]*Account{
				1: {ID: 1, Platform: PlatformOpenAI, Credentials: map[string]any{"model_mapping": map[string]any{"gpt-5.1-codex": "gpt-5.1-codex"}}},
				2: {ID: 2, Platform: PlatformOpenAI, Credentials: map[string]any{"model_mapping": map[string]any{"gpt-5.2-codex": "gpt-5.2-codex"}}},
			},
		}
		svc := &adminServiceImpl{accountRepo: repo}

		result, err := svc.BulkUpdateAccounts(context.Background(), &BulkUpdateAccountsInput{
			AccountIDs: []int64{1, 2},
			Credentials: map[string]any{
				"model_mapping": map[string]any{"gpt-5.3-codex": "gpt-5.3-codex"},
			},
			EditExistingModelMapping: false,
		})

		require.NoError(t, err)
		require.Equal(t, 2, result.Success)
	})
}
