
    async def reconcile_mcp_contexts(self, 
                                   local_context_id: str,
                                   remote_context_id: str,
                                   merge_strategy: str = "three_way_merge"
                                  ) -> ReconciliationResult:
        """
        Reconcile two MCP contexts using the StateReconciliationEngine.
        
        Args:
            local_context_id: ID of the local context.
            remote_context_id: ID of the remote context.
            merge_strategy: Strategy to use for merging.
            
        Returns:
            ReconciliationResult: Result of the reconciliation.
        """
        start_time = time.time()
        
        try:
            local_context = await self.retrieve_context(local_context_id)
            remote_context = await self.retrieve_context(remote_context_id)
            
            if not local_context or not remote_context:
                raise ValueError("Both local and remote contexts must exist for reconciliation.")
            
            reconciliation_result = self.reconciliation_engine.reconcile_contexts(
                local_context.context_data,
                remote_context.context_data,
                merge_strategy
            )
            
            # Update metrics
            self._server_state["sync_operations"] += 1
            sync_time = (time.time() - start_time) * 1000
            self._update_performance_metric("average_sync_time_ms", sync_time)
            if sync_time > self._performance_metrics["max_sync_time_ms"]:
                self._performance_metrics["max_sync_time_ms"] = sync_time
            
            # Audit log
            self.audit.log_security_event(
                AuditEvent.DATA_OPERATION,
                f"Context reconciliation performed: {local_context_id} vs {remote_context_id}",
                AuditSeverity.INFO,
                {
                    "local_context_id": local_context_id,
                    "remote_context_id": remote_context_id,
                    "merge_strategy": merge_strategy,
                    "conflicts_resolved": len(reconciliation_result.conflicts),
                    "sync_time_ms": sync_time,
                    "success": reconciliation_result.success
                }
            )
            
            self.logger.info(f"Context reconciliation completed in {sync_time:.2f}ms. Conflicts: {len(reconciliation_result.conflicts)}")
            
            return reconciliation_result
            
        except Exception as e:
            self._server_state["security_violations"] += 1
            self.audit.log_security_event(
                AuditEvent.OPERATION_FAILURE,
                f"Context reconciliation failed: {str(e)}",
                AuditSeverity.CRITICAL,
                {
                    "local_context_id": local_context_id,
                    "remote_context_id": remote_context_id,
                    "operation": "reconcile_contexts",
                    "error": str(e)
                }
            )
            self.logger.error(f"Context reconciliation failed: {e}")
            raise
